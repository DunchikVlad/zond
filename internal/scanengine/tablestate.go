package scanengine

// tableState — локальный буфер таблицы (вызовы LLM + парные аудит-события,
// п. 10.6/14.2). S8-2 (п. 13.2, max_concurrent_tables>1): воркеры движка
// обрабатывают таблицы параллельно — разделяемые буферы Engine заменены на
// структуру, принадлежащую обработке одной таблицы. Коммит — в той же
// транзакции, что и вердикты (п. 13); take* отдают и обнуляют содержимое.

import (
	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

type tableState struct {
	calls  []store.AgentCall
	events []audit.Event
}

// newTableState — пустой буфер таблицы (принадлежит одному воркеру).
func (e *Engine) newTableState() *tableState { return &tableState{} }

// reset очищает буфер перед новой попыткой таблицы (retry): записи
// неудачной попытки не попадают в чужой коммит (п. 13).
func (t *tableState) reset() {
	t.calls = nil
	t.events = nil
}

// drop — освобождение буфера после коммита/отказа таблицы (GC-хинт;
// семантика не меняется — take* уже обнулили содержимое).
func (t *tableState) drop() { t.reset() }

// takeCalls возвращает буфер вызовов таблицы и очищает его (передача в
// транзакцию п. 13).
func (t *tableState) takeCalls() []store.AgentCall {
	calls := t.calls
	t.calls = nil
	return calls
}

// takeEvents — буфер аудит-событий таблицы (ADR-0013), коммит с вердиктами.
func (t *tableState) takeEvents() []audit.Event {
	events := t.events
	t.events = nil
	return events
}
