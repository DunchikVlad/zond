package evalset

import "github.com/DunchikVlad/zond/internal/verdict"

// Словари генератора: «говорящие» и нейтральные имена колонок, ФИО, города,
// улицы, шаблоны свободного текста, домены и слова email (blueprint п. 16.6).
// Минимальные размеры закреплены тестами evalset_test.go.

// columnNames — пулы «говорящих» имён колонок по лейблу (RU/EN, слой 0).
var columnNames = map[verdict.Label][]string{
	"PERSON_NAME":     {"full_name", "fio", "customer_name", "фио", "contact_person", "employee_name", "holder_name", "person"},
	"PHONE":           {"phone", "mobile", "phone_number", "телефон", "contact_phone", "cell", "tel_number", "msisdn", "phone_no"},
	"EMAIL":           {"email", "e_mail", "почта", "email_address", "mail_box", "contact_email", "e-mail", "электронная_почта"},
	"ADDRESS":         {"address", "addr", "home_address", "адрес", "legal_address", "фактический_адрес", "residence", "post_address"},
	"CARD_NUMBER":     {"card_number", "card_no", "pan", "card_pan", "номер_карты", "cc_number", "card_num", "debit_card"},
	"BANK_ACCOUNT":    {"bank_account", "account_number", "счёт", "расчётный_счёт", "settlement_account", "iban", "acc_no", "корсчёт"},
	"PASSPORT_ID":     {"passport", "passport_no", "паспорт", "passport_series", "паспортные_данные", "pass_id", "series_number"},
	"TAX_ID":          {"inn", "tin", "tax_id", "инн", "taxpayer_id", "inn_number", "налоговый_номер"},
	"SNILS":           {"snils", "снилс", "snils_number", "пенсионный_номер", "snils_id", "snils_no"},
	"IP_ADDRESS":      {"ip", "ip_address", "client_ip", "remote_ip", "host_ip", "ipv4", "айпи"},
	"DATE_OF_BIRTH":   {"birth_date", "dob", "дата_рождения", "birthday", "date_of_birth", "bdate", "родился"},
	"GEO_LOCATION":    {"geo", "coordinates", "координаты", "lat_lon", "location", "геопозиция", "geo_point", "latlng"},
	"FREE_TEXT":       {"comment", "notes", "description", "комментарий", "заметки", "review_text", "отзыв", "free_text", "note_text"},
	"NUMERIC_MEASURE": {"value", "amount", "quantity", "metric", "число", "показатель", "measurement", "величина", "score", "measure_val"},
	"IDENTIFIER":      {"id", "uid", "uuid", "identifier", "идентификатор", "object_id", "record_id", "external_id"},
	"DATE_TIME":       {"created_at", "updated_at", "dt", "дата", "timestamp", "event_date", "registered_at", "modified_on"},
	"BOOLEAN":         {"is_active", "enabled", "flag", "активен", "deleted", "boolean_flag", "archived", "is_deleted"},
	"JSON_DOC":        {"payload", "metadata", "meta", "json_data", "атрибуты", "extra", "attributes", "properties", "doc_json"},
	"UNKNOWN":         {"ref_code", "blob", "misc", "unknown_field", "прочее", "raw_value", "code_x", "misc_data"},
}

// spoofNames — «имитирующие» имена колонок спуфов (похожи на реальные,
// но значения с битыми контрольными суммами).
var spoofNames = map[verdict.Label][]string{
	"TAX_ID":       {"inn_raw", "inn_prev", "inn_str", "tax_id_tmp", "old_inn", "inn_txt"},
	"SNILS":        {"snils_old", "snils_tmp", "snils_txt", "snils_prev", "snils_str", "pens_no"},
	"CARD_NUMBER":  {"pan_txt", "pan_old", "card_raw", "cc_tmp", "card_number_str", "pan_legacy"},
	"BANK_ACCOUNT": {"iban_text", "iban_legacy", "account_txt", "acc_raw", "iban_str", "rs_old"},
}

// freeTextNames — нейтральные имена колонок свободного текста со встроенным PII.
var freeTextNames = []string{
	"comment", "note", "feedback", "review", "message", "отзыв", "комментарий",
	"заметка", "описание", "review_body", "note_text", "reply", "текст",
}

// mixedNames / polyNames — нейтральные имена mixed/полиморфных колонок.
var mixedNames = []string{
	"value", "data", "field", "attr", "item", "val", "значение", "raw", "mix", "entry",
}

var polyNames = []string{
	"doc", "document", "payload_raw", "obj", "record", "entry_json", "blob_json", "items", "запись",
}

// surnamesRU — русские фамилии (≥40).
var surnamesRU = []string{
	"Иванов", "Петров", "Сидоров", "Смирнов", "Кузнецов", "Попов", "Васильев", "Волков",
	"Соколов", "Михайлов", "Новиков", "Фёдоров", "Морозов", "Павлов", "Голубев", "Виноградов",
	"Богданов", "Воробьёв", "Фролов", "Медведев", "Ершов", "Захаров", "Романов", "Осипов",
	"Белов", "Тарасов", "Королёв", "Гусев", "Титов", "Кудрявцев", "Баранов", "Куликов",
	"Алексеев", "Степанов", "Яковлев", "Сорокин", "Сергеев", "Козлов", "Николаев", "Зайцев",
	"Андреев", "Тихонов", "Прохоров", "Макаров", "Антонов", "Григорьев", "Егоров", "Лебедев",
}

// firstNamesRU — русские имена (≥40).
var firstNamesRU = []string{
	"Александр", "Дмитрий", "Максим", "Сергей", "Андрей", "Алексей", "Артём", "Илья",
	"Кирилл", "Михаил", "Никита", "Павел", "Роман", "Егор", "Владимир", "Тимур",
	"Иван", "Денис", "Марк", "Константин", "Олег", "Ярослав", "Степан", "Виктор",
	"Мария", "Анна", "Елена", "Ольга", "Наталья", "Ирина", "Екатерина", "Татьяна",
	"Светлана", "Юлия", "Анастасия", "Виктория", "Дарья", "Полина", "Ксения", "Валерия",
	"Оксана", "Людмила", "Галина", "Марина", "Софья", "Алина", "Вероника", "Кристина",
}

// patronymicsRU — русские отчества (≥25).
var patronymicsRU = []string{
	"Александрович", "Дмитриевич", "Сергеевич", "Андреевич", "Алексеевич", "Максимович",
	"Иванович", "Павлович", "Романович", "Егорович", "Владимирович", "Николаевич",
	"Константинович", "Олегович", "Ярославович", "Степанович", "Викторович", "Михайлович",
	"Александровна", "Дмитриевна", "Сергеевна", "Андреевна", "Алексеевна", "Ивановна",
	"Павловна", "Николаевна", "Владимировна", "Егоровна", "Максимовна",
}

// firstNamesEN — английские имена (для EN-ФИО и локальных частей email).
var firstNamesEN = []string{
	"James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda",
	"William", "Elizabeth", "David", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
	"Thomas", "Sarah", "Charles", "Karen", "Christopher", "Nancy", "Daniel", "Lisa",
	"Matthew", "Betty", "Anthony", "Margaret", "Mark", "Sandra", "Donald", "Ashley",
	"Steven", "Dorothy", "Paul", "Kimberly", "Andrew", "Emily", "Joshua", "Michelle",
	"Kevin", "Amanda", "Brian", "Melissa", "George", "Deborah", "Timothy", "Stephanie",
}

// lastNamesEN — английские фамилии (≥40).
var lastNamesEN = []string{
	"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
	"Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
	"Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
	"White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker",
	"Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
	"Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
	"Carter", "Roberts", "Gomez", "Phillips", "Evans", "Turner", "Parker", "Collins",
}

// emailWords — слова для локальной части email.
var emailWords = []string{
	"ivan", "petr", "anna", "marina", "alex", "support", "sales", "info", "mail",
	"user", "client", "admin", "test", "demo", "noreply", "office", "hr", "billing",
	"max", "olga", "dmitry", "elena", "sergey", "natalia", "order", "feedback",
}

// emailDomains — домены для email-адресов.
var emailDomains = []string{
	"gmail.com", "yandex.ru", "mail.ru", "outlook.com", "example.com",
	"gmail.com", "yandex.ru", "mail.ru", // чаще встречающиеся
}

// citiesRU — города для адресов (≥25).
var citiesRU = []string{
	"Москва", "Санкт-Петербург", "Новосибирск", "Екатеринбург", "Казань", "Нижний Новгород",
	"Самара", "Омск", "Челябинск", "Ростов-на-Дону", "Уфа", "Волгоград", "Красноярск",
	"Воронеж", "Пермь", "Краснодар", "Тюмень", "Тольятти", "Ижевск", "Барнаул",
	"Ульяновск", "Иркутск", "Хабаровск", "Ярославль", "Владивосток", "Махачкала",
	"Томск", "Оренбург", "Кемерово", "Рязань", "Сочи", "Калининград", "Владимир",
}

// streetsRU — улицы для адресов (≥30).
var streetsRU = []string{
	"Ленина", "Пушкина", "Гагарина", "Мира", "Садовая", "Советская", "Октябрьская",
	"Комсомольская", "Первомайская", "Горького", "Чехова", "Тургенева", "Достоевского",
	"Некрасова", "Маяковского", "Лермонтова", "Гоголя", "Кирова", "Энгельса", "Маркса",
	"Фрунзе", "Дзержинского", "Калинина", "Будённого", "Ворошилова", "Строителей",
	"Молодёжная", "Школьная", "Цветочная", "Зелёная", "Солнечная", "Берёзовая",
	"Полевая", "Луговая", "Речная", "Юбилейная", "Парковая", "Лесная", "Вокзальная",
	"Московская", "Тверская", "Набережная", "Пролетарская", "Рабочая", "Верхняя",
}

// freeTextTemplatesRU/EN — предложения со встроенным PII (%s — значение).
var freeTextTemplatesRU = []string{
	"Звоните мне по %s после 18:00, договоримся о встрече.",
	"Свяжитесь, пожалуйста, по номеру %s, лучше в вечернее время.",
	"Мои контакты: %s. Отвечу в течение дня.",
	"Реквизиты для перевода: %s, получатель — ИП Смирнов О.В.",
	"Отправьте документы на почту %s, я посмотрю и отвечу.",
	"Позвоните по %s, спросите Андрея.",
	"Ваш ИНН %s не прошёл проверку, обновите данные в профиле.",
	"Номер карты для возврата средств: %s.",
	"СНИЛС сотрудника %s указан в заявлении.",
	"Напишите на %s или позвоните после обеда.",
	"Клиент оставил контакт %s, просил перезвонить.",
	"Заявка обработана, уведомление отправлено на %s.",
}

var freeTextTemplatesEN = []string{
	"Call me at %s after 6pm and we'll arrange the meeting.",
	"Reach me at %s or just reply here.",
	"Send the documents to %s and I'll get back to you.",
	"Payment details: %s. Thanks in advance!",
	"My card is %s, expiry next month.",
	"Contact %s for delivery questions.",
	"Please confirm your tax id %s before invoicing.",
	"The refund goes to %s, card ending matches.",
	"Support reached out to %s but got no answer.",
	"Use %s for the wire transfer.",
}

// freeTextCleanRU/EN — короткие тексты БЕЗ PII (для разнообразия колонок
// FREE_TEXT: в одну колонку вшивается ровно один тип PII, но не каждое
// значение его содержит — встречаются и чистые предложения).
var freeTextCleanRU = []string{
	"Отличный сервис, всё быстро и понятно.",
	"Доставили на следующий день, спасибо!",
	"Качество на высоте, рекомендую.",
	"Пришлось ждать дольше обычного, но результат хороший.",
	"Пользуюсь уже третий год, претензий нет.",
	"Цена выше, чем у конкурентов, но оно того стоило.",
	"Интерфейс стал удобнее после обновления.",
	"Вежливый оператор, вопрос решён за пять минут.",
}

var freeTextCleanEN = []string{
	"Great service, fast and clear.",
	"Arrived the next day, thanks!",
	"Top quality, highly recommend.",
	"Took longer than usual, but the result is good.",
	"Third year as a customer, no complaints.",
	"Pricier than competitors, but worth it.",
	"The interface got better after the update.",
	"Polite support, issue solved in five minutes.",
}

// jsonWords — короткие слова для JSON-документов и строковых элементов.
var jsonWords = []string{
	"alpha", "beta", "item", "tag", "name", "city", "mode", "type", "status", "note",
	"temp", "speed", "level", "group", "unit", "flag", "desc", "code", "label", "kind",
}

// dominantLabels — доминантные лейблы mixed-колонок (Mongo mixed-типы):
// 40 колонок с доминантой + 20 chaos при базовой квоте 60.
var dominantLabels = []verdict.Label{"PHONE", "EMAIL", "DATE_TIME", "NUMERIC_MEASURE", "PERSON_NAME"}

// embeddedCycle — ротация встраиваемого PII по free_text-колонкам.
var embeddedCycle = []verdict.Label{"PHONE", "EMAIL", "TAX_ID", "SNILS", "CARD_NUMBER"}
