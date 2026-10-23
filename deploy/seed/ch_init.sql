-- Seed ClickHouse для smoke-контура (blueprint п. 15, DoD п. 22):
-- клиенты с PII (email/телефон) и чистые значения. Запускается образом
-- clickhouse-server из /docker-entrypoint-initdb.d при первом старте тома.
CREATE TABLE IF NOT EXISTS customers (
    id UInt32,
    email String,
    phone String,
    full_name String,
    comment String
) ENGINE = MergeTree ORDER BY id;

INSERT INTO customers VALUES
    (1, 'ivan.petrov@example.com',  '+7 916 123-45-67', 'Иван Петров',    'обычный комментарий без PII'),
    (2, 'maria.ivanova@example.com','+7 925 555-01-02', 'Мария Иванова',  'предпочитает email'),
    (3, 'test@example.org',         '84951234567',      'Тест Тестов',    'московский номер без +7'),
    (4, 'not-an-email',             'телефон неизвестен','Без Контактов', 'негативный пример'),
    (5, 'oleg.smirnov@corp.ru',     '+7 903 111-22-33', 'Олег Смирнов',   'VIP-клиент'),
    (6, 'anna.kuznetsova@mail.io',  '8 926 444 55 66',  'Анна Кузнецова', 'просила звонить после 18'),
    (7, 'info@example.com',         'unknown',          'Робот Роботов',  'техническая учётка'),
    (8, 'petr.volkov@example.com',  '+7 495 777-88-99', 'Пётр Волков',    'дубликат по телефону офиса');
