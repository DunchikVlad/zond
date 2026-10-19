// Обработчики вердиктов REST API (blueprint п. 11.2): фильтрованный список
// с сортировкой risk_first, карточка с журналом ревью, ручное ревью
// (confirm/reject/relabel), экспорт CSV/JSON. Ревью и экспорт аудируются
// (п. 14.2, fail-closed); evidence в ответах уже маскирован (ADR-0010).
package api

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// verdictDTO — вердикт в API (п. 5.4; evidence — маскированный, ADR-0010).
type verdictDTO struct {
	ID               string                `json:"id"`
	ScanID           string                `json:"scan_id"`
	Table            string                `json:"table"`
	Path             string                `json:"path"`
	NativeType       string                `json:"native_type"`
	Label            verdict.Label         `json:"label"`
	FinalLabel       verdict.Label         `json:"final_label,omitempty"`
	Sensitivity      verdict.Sensitivity   `json:"sensitivity"`
	Confidence       float64               `json:"confidence"`
	EvidenceLayer    verdict.EvidenceLayer `json:"evidence_layer"`
	Evidence         map[string]any        `json:"evidence"`
	TaxonomyVersion  string                `json:"taxonomy_version"`
	DetectorsVersion string                `json:"detectors_version"`
	PromptVersion    string                `json:"prompt_version,omitempty"`
	SampleSize       int                   `json:"sample_size"`
	ClusterID        string                `json:"cluster_id,omitempty"`
	ReviewStatus     verdict.ReviewStatus  `json:"review_status"`
	ReviewedBy       string                `json:"reviewed_by,omitempty"`
	ReviewedAt       *time.Time            `json:"reviewed_at,omitempty"`
	CreatedAt        time.Time             `json:"created_at"`
}

func toVerdictDTO(v *verdict.Verdict) verdictDTO {
	dto := verdictDTO{
		ID: v.ID, ScanID: v.ScanID, Table: v.Table, Path: v.Path,
		NativeType: v.NativeType, Label: v.Label, FinalLabel: v.FinalLabel,
		Sensitivity: v.Sensitivity, Confidence: v.Confidence,
		EvidenceLayer: v.EvidenceLayer, Evidence: v.Evidence,
		TaxonomyVersion: v.TaxonomyVersion, DetectorsVersion: v.DetectorsVersion,
		PromptVersion: v.PromptVersion, SampleSize: v.SampleSize,
		ClusterID: v.ClusterID, ReviewStatus: v.ReviewStatus,
		ReviewedBy: v.ReviewedBy, CreatedAt: v.CreatedAt,
	}
	if !v.ReviewedAt.IsZero() {
		t := v.ReviewedAt
		dto.ReviewedAt = &t
	}
	if dto.Evidence == nil {
		dto.Evidence = map[string]any{}
	}
	return dto
}

// handleVerdictList — GET /api/v1/verdicts?scan_id=&label=&sensitivity=
// &min_conf=&review_status=&table=&cluster_id=&sort=risk_first&limit=&offset=
func (s *Server) handleVerdictList(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := pageParams(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(), nil)
		return
	}
	q := r.URL.Query()
	f := store.VerdictFilter{
		ScanID: q.Get("scan_id"), Label: q.Get("label"),
		Sensitivity: q.Get("sensitivity"), ReviewStatus: q.Get("review_status"),
		Table: q.Get("table"), ClusterID: q.Get("cluster_id"),
		RiskFirst: q.Get("sort") == "risk_first",
		Limit:     limit, Offset: offset,
	}
	if v := q.Get("min_conf"); v != "" {
		c, err := strconv.ParseFloat(v, 64)
		if err != nil || c < 0 || c > 1 {
			writeError(w, http.StatusBadRequest, CodeInvalidRequest,
				"min_conf: ожидается число в [0,1]", nil)
			return
		}
		f.MinConf = c
	}
	vs, total, err := s.st.ListVerdictsFiltered(r.Context(), f)
	if err != nil {
		s.internalError(w, r, "список вердиктов", err)
		return
	}
	items := make([]verdictDTO, 0, len(vs))
	for i := range vs {
		items = append(items, toVerdictDTO(&vs[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

// handleVerdictGet — GET /api/v1/verdicts/{id}: детали + журнал ревью
// (п. 11.2; evidence маскирован ещё на записи, ADR-0010).
func (s *Server) handleVerdictGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	v, err := s.st.GetVerdict(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "verdict_not_found", "вердикт не найден",
			map[string]string{"verdict_id": id})
		return
	}
	if err != nil {
		s.internalError(w, r, "карточка вердикта", err)
		return
	}
	events, err := s.st.ListReviewEvents(r.Context(), id)
	if err != nil {
		s.internalError(w, r, "журнал ревью", err)
		return
	}
	if events == nil {
		events = []store.ReviewEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"verdict":       toVerdictDTO(v),
		"review_events": events,
	})
}

// reviewRequest — тело POST /api/v1/verdicts/{id}/review (п. 11.2).
type reviewRequest struct {
	Action string `json:"action"` // confirm | reject | relabel
	Label  string `json:"label"`  // обязателен для relabel
}

// handleReview — POST /api/v1/verdicts/{id}/review: смена review_status +
// review_events + аудит одной транзакцией (п. 13/14.2). Конфликты
// (повторное действие, relabel на тот же лейбл) — 409 review_conflict.
func (s *Server) handleReview(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req reviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "тело запроса: "+err.Error(), nil)
		return
	}
	action := store.ReviewAction(req.Action)
	if action != store.ReviewConfirm && action != store.ReviewReject && action != store.ReviewRelabel {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			"action: ожидается confirm|reject|relabel", nil)
		return
	}
	if action == store.ReviewRelabel && req.Label == "" {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			"relabel требует поле label", nil)
		return
	}
	v, err := s.st.ApplyReview(r.Context(), id, action, verdict.Label(req.Label), Actor, s.nowFn())
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "verdict_not_found", "вердикт не найден",
			map[string]string{"verdict_id": id})
		return
	}
	var conflict *store.ReviewConflict
	if errors.As(err, &conflict) {
		writeError(w, http.StatusConflict, CodeReviewConflict, conflict.Error(), nil)
		return
	}
	if err != nil {
		s.internalError(w, r, "ревью вердикта", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"verdict": toVerdictDTO(v)})
}

// handleExport — GET /api/v1/export?scan_id=&format=csv|json (п. 11.2):
// выгрузка вердиктов прогона. Лимит export_max_rows — при превышении 409 с
// предложением async-экспорта (задел п. 11.2). Экспорт аудируется ДО выдачи
// данных (fail-closed, п. 14.2).
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	scanID := q.Get("scan_id")
	if scanID == "" {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "параметр scan_id обязателен", nil)
		return
	}
	format := q.Get("format")
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "format: ожидается csv|json", nil)
		return
	}
	if _, err := s.st.GetScan(r.Context(), scanID); errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, CodeScanNotFound, "прогон не найден",
			map[string]string{"scan_id": scanID})
		return
	} else if err != nil {
		s.internalError(w, r, "карточка прогона", err)
		return
	}
	vs, total, err := s.st.VerdictsForExport(r.Context(), scanID, s.maxRows)
	if err != nil {
		s.internalError(w, r, "выгрузка вердиктов", err)
		return
	}
	if vs == nil && total > s.maxRows {
		writeError(w, http.StatusConflict, CodeInvalidRequest,
			fmt.Sprintf("строк %d превышает export_max_rows=%d: используйте async-экспорт", total, s.maxRows),
			map[string]any{"rows": total, "export_max_rows": s.maxRows, "async": true})
		return
	}
	// Экспорт — аудируемое действие (п. 14.2): запись до выдачи данных;
	// ошибка аудита = экспорт не выполняется (fail-closed).
	if err := s.auditEvent(r.Context(), audit.CatExport, "verdicts_export", "export", map[string]any{
		"scan_id": scanID, "rows": len(vs), "format": format,
	}); err != nil {
		s.internalError(w, r, "аудит экспорта", err)
		return
	}
	switch format {
	case "csv":
		s.writeExportCSV(w, scanID, vs)
	default:
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`attachment; filename="zond-export-%s.json"`, scanID))
		items := make([]verdictDTO, 0, len(vs))
		for i := range vs {
			items = append(items, toVerdictDTO(&vs[i]))
		}
		writeJSON(w, http.StatusOK, map[string]any{"scan_id": scanID, "items": items, "total": len(items)})
	}
}

// exportCSVHeader — колонки CSV-выгрузки (п. 11.2; evidence — JSON-строкой,
// значения внутри маскированы на записи, ADR-0010).
var exportCSVHeader = []string{
	"id", "scan_id", "table", "path", "native_type", "label", "final_label",
	"sensitivity", "confidence", "evidence_layer", "review_status",
	"reviewed_by", "reviewed_at", "sample_size", "cluster_id",
	"taxonomy_version", "detectors_version", "prompt_version", "created_at", "evidence",
}

func (s *Server) writeExportCSV(w http.ResponseWriter, scanID string, vs []verdict.Verdict) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="zond-export-%s.csv"`, scanID))
	w.WriteHeader(http.StatusOK)
	cw := csv.NewWriter(w)
	_ = cw.Write(exportCSVHeader)
	for i := range vs {
		v := &vs[i]
		ev, err := json.Marshal(v.Evidence)
		if err != nil {
			ev = []byte("{}")
		}
		reviewedAt := ""
		if !v.ReviewedAt.IsZero() {
			reviewedAt = v.ReviewedAt.UTC().Format(time.RFC3339)
		}
		_ = cw.Write([]string{
			v.ID, v.ScanID, v.Table, v.Path, v.NativeType,
			string(v.Label), string(v.FinalLabel), string(v.Sensitivity),
			strconv.FormatFloat(v.Confidence, 'f', 4, 64), string(v.EvidenceLayer),
			string(v.ReviewStatus), v.ReviewedBy, reviewedAt,
			strconv.Itoa(v.SampleSize), v.ClusterID,
			v.TaxonomyVersion, v.DetectorsVersion, v.PromptVersion,
			v.CreatedAt.UTC().Format(time.RFC3339), string(ev),
		})
	}
	cw.Flush()
}
