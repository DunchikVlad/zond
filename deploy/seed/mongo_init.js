// Seed MongoDB для smoke-контура (blueprint п. 15, DoD п. 22): коллекция
// customers с PII-полями и смешанными типами. Образ mongo запускает
// /docker-entrypoint-initdb.d/*.js при первом старте тома (под root-пользователем).
db = db.getSiblingDB('smoke');

db.customers.insertMany([
  { _id: 1, email: 'ivan.petrov@example.com', phone: '+7 916 123-45-67', full_name: 'Иван Петров',  comment: 'обычный комментарий без PII' },
  { _id: 2, email: 'maria.ivanova@example.com', phone: '+7 925 555-01-02', full_name: 'Мария Иванова', comment: 'предпочитает email' },
  { _id: 3, email: 'test@example.org', phone: '84951234567', full_name: 'Тест Тестов', comment: 'московский номер без +7' },
  { _id: 4, email: 'not-an-email', phone: 'телефон неизвестен', full_name: 'Без Контактов', comment: 'негативный пример' },
  { _id: 5, email: 'oleg.smirnov@corp.ru', phone: '+7 903 111-22-33', full_name: 'Олег Смирнов', comment: 'VIP-клиент' },
  { _id: 6, email: 'anna.kuznetsova@mail.io', phone: '8 926 444 55 66', full_name: 'Анна Кузнецова', comment: 'просила звонить после 18' },
  { _id: 7, email: 'info@example.com', phone: 'unknown', full_name: 'Робот Роботов', comment: 'техническая учётка' },
  { _id: 8, email: 'petr.volkov@example.com', phone: '+7 495 777-88-99', full_name: 'Пётр Волков', comment: 'дубликат по телефону офиса' }
]);
