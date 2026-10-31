// Обработчики агентского описания БД REST API (S9-4, blueprint S9 п. 5):
// старт прогона описания, список и карточка прогона. Старт/ошибки аудируются.
package api

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// handleDescriptionStart — POST /api/v1/scans/{id}/description-runs
// Запускает агентский прогон описания БД по scan_id (S9-4).
// Скан должен быть в терминальном статусе; partial — с пометкой неполного снимка.
// Требует ActionScan (admin); аудит description_start пишет runner (fail-closed).
func (s *Server) handleDescriptionStart(w http.ResponseWriter, r *http.Request) {
	if s.descRunner == nil {
		writeError(w, http.StatusNotImplemented, CodeInvalidRequest,
			"генерация описания недоступна: сервер без description runner", nil)
		return
	}
	scanID := r.PathValue("id")
	// Проверяем, что скан существует и в терминальном статусе
	sc, err := s.st.GetScan(r.Context(), scanID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, CodeScanNotFound, "прогон не найден", map[string]string{"scan_id": scanID})
		return
	}
	if err != nil {
		s.internalError(w, r, "карточка прогона", err)
		return
	}
	if !isTerminalScanStatus(sc.Status) {
		writeError(w, http.StatusConflict, CodeInvalidRequest,
			"прогон в статусе "+sc.Status+", нужен терминальный (done/partial/failed/budget_exceeded)",
			map[string]string{"scan_id": scanID, "status": sc.Status})
		return
	}
	// Запускаем прогон описания (синхронно — описание быстрое, один LLM-вызов)
	dr, err := s.descRunner.Run(r.Context(), scanID, s.actorFromCtx(r))
	if err != nil {
		s.internalError(w, r, "запуск описания", err)
		return
	}
	writeJSON(w, http.StatusAccepted, dr.ToDTO())
}

// handleDescriptionList — GET /api/v1/scans/{id}/description-runs
// Возвращает историю прогонов описания для скана (S9-4).
func (s *Server) handleDescriptionList(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")
	// Проверяем, что скан существует
	_, err := s.st.GetScan(r.Context(), scanID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, CodeScanNotFound, "прогон не найден", map[string]string{"scan_id": scanID})
		return
	}
	if err != nil {
		s.internalError(w, r, "карточка прогона", err)
		return
	}
	runs, err := s.st.ListDescriptionRuns(r.Context(), scanID)
	if err != nil {
		s.internalError(w, r, "список описаний", err)
		return
	}
	items := make([]map[string]any, 0, len(runs))
	for i := range runs {
		items = append(items, runs[i].ToDTO())
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

// handleDescriptionGet — GET /api/v1/description-runs/{id}
// Возвращает карточку прогона описания (S9-4).
func (s *Server) handleDescriptionGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dr, err := s.st.GetDescriptionRun(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, CodeInvalidRequest, "прогон описания не найден", map[string]string{"description_run_id": id})
		return
	}
	if err != nil {
		s.internalError(w, r, "карточка описания", err)
		return
	}
	writeJSON(w, http.StatusOK, dr.ToDTO())
}

// isTerminalScanStatus — скан в терминальном статусе (можно описывать).
func isTerminalScanStatus(s string) bool {
	switch s {
	case "done", "partial", "failed", "budget_exceeded":
		return true
	}
	return false
}

// storeUsed — маркер использования store (для компилятора).
var _ = store.DescriptionRun{}
