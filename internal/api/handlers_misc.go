// Обработчики дрейфа и экономики (blueprint п. 11.2): GET /api/v1/drift —
// дифф двух последних прогонов источника; GET /api/v1/stats/cost —
// токены/стоимость по агентам и моделям (п. 17).
package api

import (
	"net/http"
	"time"

	"github.com/DunchikVlad/zond/internal/verdict/drift"
)

// handleDrift — GET /api/v1/drift?source=&since= (п. 11.2): новые/
// исчезнувшие колонки, смены лейблов/уверенности между двумя последними
// завершёнными прогонами источника (since ограничивает период снизу).
func (s *Server) handleDrift(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	source := q.Get("source")
	if source == "" {
		// совместимость с blueprint (source_id) — имя параметра в конфиге
		// источников одно: name; API принимает оба.
		source = q.Get("source_id")
	}
	if source == "" {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			"параметр source обязателен", nil)
		return
	}
	var since *time.Time
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, CodeInvalidRequest,
				"since: формат RFC3339", nil)
			return
		}
		since = &t
	}
	rep, ok, err := drift.BetweenLatest(r.Context(), s.st, source, since)
	if err != nil {
		s.internalError(w, r, "дрейф", err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, CodeInvalidRequest,
			"недостаточно завершённых прогонов для сравнения (нужно ≥2)",
			map[string]string{"source": source})
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// handleCost — GET /api/v1/stats/cost?scan_id= (п. 11.2, п. 17): токены,
// стоимость, латентность по агентам/моделям + доля решённого без LLM.
func (s *Server) handleCost(w http.ResponseWriter, r *http.Request) {
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "параметр scan_id обязателен", nil)
		return
	}
	stats, err := s.st.ScanCostStats(r.Context(), scanID)
	if err != nil {
		s.internalError(w, r, "экономика прогона", err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}
