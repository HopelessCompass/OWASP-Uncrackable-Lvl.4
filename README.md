# OWASP-Uncrackable-Lvl.4
Reverse Engineering Journal — OWASP Uncrackable Lvl.4 (Android, Native, Smali)

Я не супер-профи, но упорно ковыряюсь и учусь. Это журнал всей работы, чтобы самой понимать путь, и чтобы другие новички могли видеть, что всё реально

## I. Исходная задача
Разобрать и пропатчить Android-приложение OWASP Uncrackable Level 4, которое:
1. Использует RootBeer для анти-рут детекции
2. Вызывает нативную функцию gXftm3iswpkVgBNDUp(...) из libnative-lib.so
3. Проверяет введённый PIN и сумму
4. Собирает их в буфер - шифрует/кодирует - выдаёт r2coin-токен
5. Валидность токена определяется цветом и первым байтом ответа

## II. Обход защит от взлома (проверка на рута)
Найдена логика root-чеков в Smali в методе
```
.method public j()Z
```
который вызывает цепочку проверок:
1. h() - опасные пакеты
2. g() - опасные приложения
3. a("su") — поиск бинаря su
4. b() — опасные props
5. d() — монтирования в режиме RW
6. i() — test-keys
7. f() — which su
8. e() — native RootBeer
9. c() — "magisk"

Пропатчено в Smali (полностью заменено содержимое):
```
.method public j()Z
    .locals 1

    const/4 v0, 0x0
    return v0

.end method
```

Это гарантирует, что приложение всегда будет думать утройство не рутовано

## III. Почему оно всё равно падало (важный вывод)
Фейл был не в патче j(). В оригинальной Java-логике есть ловушка:
```
if (rb.m2456j() || (rb.m2441a() && rb.m2451e())) {
    int i = 1337 / 0;   // <-- явное падение
    this.f2369a = (byte) (this.f2369a | 15);
}
```
Если RootBeer обнаруживает root раньше — приложение крашится до вызова пропатченного j().

### Был выбран вариант с пропатчиванием Smali метода проверки
Патчить будем метод OnCreate. Он выглядит очень нагруженно и я не буду прикладывать его листинг.
Нас интересует следующий блок и переходы которые ведут к нему:
```
:cond_0
const/16 v1, 0x539
div-int/lit8 v1, v1, 0x0   # <-- крэш
...
```
### Было:
```
.line 37
.local v0, "rb":Lb/a/a/b;
invoke-virtual {v0}, Lb/a/a/b;->j()Z
move-result v1
if-nez v1, :cond_0
invoke-virtual {v0}, Lb/a/a/b;->a()Z
move-result v1
if-eqz v1, :cond_1
invoke-virtual {v0}, Lb/a/a/b;->e()Z
move-result v1
if-eqz v1, :cond_1
.line 38
:cond_0
const/16 v1, 0x539
div-int/lit8 v1, v1, 0x0
...
:cond_1
invoke-virtual {p0}, Lre/pwnme/MainActivity;->g()V
```

После патча:
```
.line 37
.local v0, "rb":Lb/a/a/b;
# МОЙ ПАТЧ
goto :cond_1
# ДАЛЬШЕ ВСЁ ОСТАВЛЯЕМ КАК ЕСТЬ (оно станет мёртвым кодом)
invoke-virtual {v0}, Lb/a/a/b;->j()Z
move-result v1
if-nez v1, :cond_0
invoke-virtual {v0}, Lb/a/a/b;->a()Z
move-result v1
if-eqz v1, :cond_1
invoke-virtual {v0}, Lb/a/a/b;->e()Z
move-result v1
if-eqz v1, :cond_1
.line 38
:cond_0
const/16 v1, 0x539
div-int/lit8 v1, v1, 0x0
...
:cond_1
invoke-virtual {p0}, Lre/pwnme/MainActivity;->g()V
```
### В результате:
1. При любом раскладе после создания rb сразу прыгаем в :cond_1
2. Другие методы не вызываются
3. Краш приложения через "1337/0" никогда не выполняется

P.S. После поисков в интернете и аналитики, я пришла к выводу, что это самый безопасный и предсказуемый обход.

## VI. Раскручивание логики приложения с генерацией правильного PIN и AMOUNT с выдачей корректного (зеленого) значения вывода
Самый простой, но не самый правильный вариант - это пропатчить так, чтобы любое значение было валидным (зеленым). Но от этого варианта я отказалась т.к. цель - именно разобрать алгоритм работы программы, т.е. как вычисляется валидное значение PIN и сумму.

1. Перехватываем memcp с помощью следующего хука Frida:
```
'use strict';

function asHex(ptr, len) {
  return ptr.readByteArray(len);
}

Interceptor.attach(Module.getExportByName(null, "memcmp"), {
  onEnter(args) {
    this.a = args[0];
    this.b = args[1];
    this.n = args[2].toInt32();

    // PIN обычно 4 байта ASCII, salt — читаемая lowercase-строка
    if (this.n === 4 || (this.n > 4 && this.n < 64)) {
      try {
        const sa = this.a.readCString();
        const sb = this.b.readCString();
        if (/^\d{4}$/.test(sa) || /^\d{4}$/.test(sb) || /^[a-z]+$/.test(sa) || /^[a-z]+$/.test(sb)) {
          console.log("[memcmp n=" + this.n + "] A:", sa, " B:", sb);
        }
      } catch (e) {}
    }
  }
});
```

To do:
1. Скормить хук приложению чтобы вычислить алгоритм вычисления валидных значений
2. Написать программу на Python которая будет генерировать валидные значения PIN и количества
3. Оформить отчёт во этом репозитории

