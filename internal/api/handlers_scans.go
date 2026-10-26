// Обработчики сканов REST API (blueprint п. 11.2): список/карточка прогона,
// асинхронный старт и мягкая остановка. Старт/стоп аудируются (п. 14.2).
package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/scanengine"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// scanDTO — представление прогона в API (stats_json отдаётся как объект).
type scanDTO struct {
	ID         string         `json:"id"`
	Source     string         `json:"source"`
	Profile    string         `json:"profile"`
	Status     string         `json:"status"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
	Stats      map[string]any `json:"stats"`
}

func toScanDTO(sc *store.Scan) scanDTO {
	dto := scanDTO{
		ID: sc.ID, Source: sc.SourceName, Profile: sc.Profile,
		Status: sc.Status, StartedAt: sc.StartedAt, FinishedAt: sc.FinishedAt,
		Stats: map[string]any{},
	}
	if sc.StatsJSON != "" {
		_ = json.Unmarshal([]byte(sc.StatsJSON), &dto.Stats)
	}
	return dto
}

// pageParams разбирает limit/offset из query (пагинация списков п. 11.2).
func pageParams(r *http.Request) (limit, offset int, err error) {
	q := r.URL.Query()
	if v := q.Get("limit"); v != "" {
		limit, err = strconv.Atoi(v)
		if err != nil || limit < 0 {
			return 0, 0, errors.New("limit: ожидается целое >= 0")
		}
	}
	if v := q.Get("offset"); v != "" {
		offset, err = strconv.Atoi(v)
		if err != nil || offset < 0 {
			return 0, 0, errors.New("offset: ожидается целое >= 0")
		}
	}
	return limit, offset, nil
}

// handleScanList — GET /api/v1/scans?status=&source=&limit=&offset=
func (s *Server) handleScanList(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := pageParams(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(), nil)
		return
	}
	q := r.URL.Query()
	scans, total, err := s.st.ListScans(r.Context(), store.ScanFilter{
		Status: q.Get("status"), Source: q.Get("source"),
		Limit: limit, Offset: offset,
	})
	if err != nil {
		s.internalError(w, r, "список прогонов", err)
		return
	}
	items := make([]scanDTO, 0, len(scans))
	for i := range scans {
		items = append(items, toScanDTO(&scans[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

// handleScanGet — GET /api/v1/scans/{id}: статус, прогресс (чекпоинты
// таблиц п. 13), stats_json.
func (s *Server) handleScanGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sc, err := s.st.GetScan(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, CodeScanNotFound, "прогон не найден", map[string]string{"scan_id": id})
		return
	}
	if err != nil {
		s.internalError(w, r, "карточка прогона", err)
		return
	}
	tables, err := s.st.ScanTables(r.Context(), id)
	if err != nil {
		s.internalError(w, r, "прогресс прогона", err)
		return
	}
	dto := toScanDTO(sc)
	writeJSON(w, http.StatusOK, map[string]any{
		"scan":   dto,
		"tables": tables,
	})
}

// startRequest — тело POST /api/v1/scans (п. 11.2): {source, profile}.
type startRequest struct {
	Source  string `json:"source"`
	Profile string `json:"profile"`
}

// handleScanStart — POST /api/v1/scans {source, profile} → {scan_id}.
// Асинхронно: прогон исполняется фоном; аудит scan_start пишет движок
// (actor api). Ошибка недоступного источника — source_unavailable (п. 11.2).
func (s *Server) handleScanStart(w http.ResponseWriter, r *http.Request) {
	if s.runner == nil {
		writeError(w, http.StatusNotImplemented, CodeInvalidRequest,
			"запуск сканов недоступен: сервер без runner", nil)
		return
	}
	var req startRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "тело запроса: "+err.Error(), nil)
		return
	}
	if req.Source == "" {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "поле source обязательно", nil)
		return
	}
	scanID, err := s.runner.Start(req.Source, req.Profile, s.actorFromCtx(r))
	if err != nil {
		var unf *SourceUnavailableError
		if errors.As(err, &unf) {
			writeError(w, http.StatusBadGateway, CodeSourceUnavailable, err.Error(), nil)
			return
		}
		var bad *BadScanRequestError
		if errors.As(err, &bad) {
			writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(), nil)
			return
		}
		s.internalError(w, r, "старт прогона", err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"scan_id": scanID, "status": "running"})
}

// handleScanResume — POST /api/v1/scans/{id}/resume: новый прогон,
// пропускающий done-таблицы после fail-closed сверки provenance.
func (s *Server) handleScanResume(w http.ResponseWriter, r *http.Request) {
	if s.runner == nil {
		writeError(w, http.StatusNotImplemented, CodeInvalidRequest,
			"продолжение сканов недоступно: сервер без runner", nil)
		return
	}
	id := r.PathValue("id")
	newID, err := s.runner.Resume(id, s.actorFromCtx(r))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, CodeScanNotFound, "прогон не найден", map[string]string{"scan_id": id})
		return
	}
	var compat *scanengine.ResumeCompatibilityError
	if errors.As(err, &compat) {
		writeError(w, http.StatusConflict, CodeResumeIncompatible, err.Error(), map[string]any{"mismatches": compat.Mismatches})
		return
	}
	var conflict *ScanConflictError
	if errors.As(err, &conflict) {
		writeError(w, http.StatusConflict, CodeInvalidRequest, err.Error(), nil)
		return
	}
	var unavailable *SourceUnavailableError
	if errors.As(err, &unavailable) {
		writeError(w, http.StatusBadGateway, CodeSourceUnavailable, err.Error(), nil)
		return
	}
	var bad *BadScanRequestError
	if errors.As(err, &bad) {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(), nil)
		return
	}
	if err != nil {
		s.internalError(w, r, "продолжение прогона", err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"scan_id": newID, "status": "running", "resume_from": id})
}

// handleScanStop — POST /api/v1/scans/{id}/stop: мягкая остановка (п. 11.2).
// Аудируется как scan/scan_stop (п. 14.2); движок фиксирует interrupted.
func (s *Server) handleScanStop(w http.ResponseWriter, r *http.Request) {
	if s.runner == nil {
		writeError(w, http.StatusNotImplemented, CodeInvalidRequest,
			"остановка сканов недоступна: сервер без runner", nil)
		return
	}
	id := r.PathValue("id")
	sc, err := s.st.GetScan(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, CodeScanNotFound, "прогон не найден", map[string]string{"scan_id": id})
		return
	}
	if err != nil {
		s.internalError(w, r, "карточка прогона", err)
		return
	}
	if sc.Status != "running" {
		writeError(w, http.StatusConflict, CodeInvalidRequest,
			"прогон уже в терминальном статусе", map[string]string{"status": sc.Status})
		return
	}
	// Аудит до действия (fail-closed, п. 14.2): остановка без аудита не
	// считается запрошенной.
	if err := s.auditEventAs(r, audit.CatScan, "scan_stop", "scan:"+id, nil); err != nil {
		s.internalError(w, r, "аудит остановки", err)
		return
	}
	if err := s.runner.Stop(id); err != nil {
		s.internalError(w, r, "остановка прогона", err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"scan_id": id, "status": "stopping"})
}

// SourceUnavailableError — источник недоступен/неизвестен при старте
// (п. 11.2 код source_unavailable).
type SourceUnavailableError struct{ Reason string }

func (e *SourceUnavailableError) Error() string { return e.Reason }

// BadScanRequestError — некорректные параметры старта (профиль и т.п.).
type BadScanRequestError struct{ Reason string }

func (e *BadScanRequestError) Error() string { return e.Reason }

// ScanConflictError — состояние прогона не допускает запрошенную операцию.
type ScanConflictError struct{ Reason string }

func (e *ScanConflictError) Error() string { return e.Reason }

// internalError — 500 с логом (code internal, п. 11.2).
func (s *Server) internalError(w http.ResponseWriter, r *http.Request, op string, err error) {
	s.log.ErrorContext(r.Context(), "api: "+op, "error", err)
	writeError(w, http.StatusInternalServerError, CodeInternal, "внутренняя ошибка", nil)
}

// handleHealth — GET /api/health: liveness (процесс жив).
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReady — GET /api/ready: readiness (store доступен). Целостность
// аудит-цепочки не проверяется на каждый запрос — это отдельная процедура
// (zond audit verify, runbook audit-hash-chain-broken.md).
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if err := s.st.Ping(r.Context()); err != nil {
		s.log.ErrorContext(r.Context(), "api: readiness", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
