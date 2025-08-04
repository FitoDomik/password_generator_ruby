#!/usr/bin/env ruby
# -*- coding: utf-8 -*-

require 'io/console'
require 'securerandom'

# Класс для генерации паролей
class PasswordGenerator
  # Наборы символов для генерации
  LOWERCASE = ('a'..'z').to_a.freeze
  UPPERCASE = ('A'..'Z').to_a.freeze
  DIGITS = ('0'..'9').to_a.freeze
  SPECIAL = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', 
             '+', '=', '[', ']', '{', '}', '|', '\\', ':', ';', '"', 
             "'", '<', '>', ',', '.', '?', '/', '~', '`'].freeze
  
  # Легко читаемые символы (без похожих: 0, O, l, 1, I)
  READABLE_LOWER = ('a'..'z').to_a - ['l', 'o'].freeze
  READABLE_UPPER = ('A'..'Z').to_a - ['I', 'O'].freeze
  READABLE_DIGITS = ('2'..'9').to_a.freeze
  READABLE_SPECIAL = ['!', '@', '#', '$', '%', '^', '&', '*', '-', '_', '+', '='].freeze

  attr_accessor :length, :include_lowercase, :include_uppercase, 
                :include_digits, :include_special, :readable_only,
                :exclude_ambiguous, :min_special, :min_digits

  def initialize
    @length = 12
    @include_lowercase = true
    @include_uppercase = true
    @include_digits = true
    @include_special = true
    @readable_only = false
    @exclude_ambiguous = false
    @min_special = 1
    @min_digits = 1
  end

  # Генерирует пароль согласно настройкам
  def generate
    charset = build_charset
    
    if charset.empty?
      raise "❌ Ошибка: Не выбрано ни одного типа символов!"
    end

    password = []
    
    # Гарантируем минимальное количество спецсимволов и цифр
    if @include_special && @min_special > 0
      special_chars = @readable_only ? READABLE_SPECIAL : SPECIAL
      @min_special.times { password << special_chars.sample }
    end
    
    if @include_digits && @min_digits > 0
      digits = @readable_only ? READABLE_DIGITS : DIGITS
      @min_digits.times { password << digits.sample }
    end
    
    # Заполняем оставшуюся часть случайными символами
    remaining_length = @length - password.length
    remaining_length.times { password << charset.sample }
    
    # Перемешиваем пароль для случайного порядка
    password.shuffle.join
  end

  # Генерирует несколько паролей
  def generate_multiple(count)
    (1..count).map { generate }
  end

  # Оценивает силу пароля
  def evaluate_strength(password)
    score = 0
    feedback = []

    # Длина
    case password.length
    when 0..7
      score += 1
      feedback << "🔴 Слишком короткий (менее 8 символов)"
    when 8..11
      score += 2
      feedback << "🟡 Средняя длина (8-11 символов)"
    when 12..15
      score += 3
      feedback << "🟢 Хорошая длина (12-15 символов)"
    else
      score += 4
      feedback << "🟢 Отличная длина (16+ символов)"
    end

    # Разнообразие символов
    has_lower = password.match?(/[a-z]/)
    has_upper = password.match?(/[A-Z]/)
    has_digit = password.match?(/[0-9]/)
    has_special = password.match?(/[^a-zA-Z0-9]/)

    variety_count = [has_lower, has_upper, has_digit, has_special].count(true)
    
    case variety_count
    when 1
      score += 1
      feedback << "🔴 Только один тип символов"
    when 2
      score += 2
      feedback << "🟡 Два типа символов"
    when 3
      score += 3
      feedback << "🟢 Три типа символов"
    when 4
      score += 4
      feedback << "🟢 Все типы символов"
    end

    # Повторяющиеся символы
    unique_chars = password.chars.uniq.length
    repetition_ratio = unique_chars.to_f / password.length
    
    if repetition_ratio < 0.5
      score += 1
      feedback << "🔴 Много повторяющихся символов"
    elsif repetition_ratio < 0.8
      score += 2
      feedback << "🟡 Некоторые символы повторяются"
    else
      score += 3
      feedback << "🟢 Мало повторений"
    end

    # Общая оценка
    strength = case score
               when 0..4 then { level: "Очень слабый", color: "🔴", emoji: "💀" }
               when 5..6 then { level: "Слабый", color: "🟠", emoji: "⚠️" }
               when 7..8 then { level: "Средний", color: "🟡", emoji: "⚡" }
               when 9..10 then { level: "Сильный", color: "🟢", emoji: "🛡️" }
               else { level: "Очень сильный", color: "🟢", emoji: "🔒" }
               end

    { score: score, strength: strength, feedback: feedback }
  end

  private

  def build_charset
    charset = []
    
    if @readable_only
      charset += READABLE_LOWER if @include_lowercase
      charset += READABLE_UPPER if @include_uppercase
      charset += READABLE_DIGITS if @include_digits
      charset += READABLE_SPECIAL if @include_special
    else
      charset += LOWERCASE if @include_lowercase
      charset += UPPERCASE if @include_uppercase
      charset += DIGITS if @include_digits
      charset += SPECIAL if @include_special
    end
    
    # Исключаем двусмысленные символы при необходимости
    if @exclude_ambiguous
      ambiguous = ['0', 'O', 'l', '1', 'I', '|', '`', "'"]
      charset -= ambiguous
    end
    
    charset
  end
end

# Класс для пользовательского интерфейса
class PasswordGeneratorUI
  def initialize
    @generator = PasswordGenerator.new
    @running = true
  end

  def start
    show_welcome
    
    while @running
      show_menu
      handle_choice(get_user_input)
    end
    
    puts "\n👋 До свидания! Используй надёжные пароли!"
  end

  private

  def show_welcome
    puts <<~WELCOME
      
      🔐 Генератор надёжных паролей на Ruby
      ═══════════════════════════════════════
      
      🛡️  Создавай безопасные пароли легко и быстро!
      🎯 Множество настроек для любых требований
      📊 Анализ силы паролей
      
    WELCOME
  end

  def show_menu
    current_settings = format_current_settings
    
    puts <<~MENU
      
      ┌─ ГЛАВНОЕ МЕНЮ ─────────────────────────────┐
      │                                            │
      │  1️⃣  Сгенерировать пароль                   │
      │  2️⃣  Сгенерировать несколько паролей        │
      │  3️⃣  Настройки генератора                   │
      │  4️⃣  Проверить силу пароля                  │
      │  5️⃣  Показать примеры                       │
      │  6️⃣  Экспорт паролей в файл                 │
      │  0️⃣  Выход                                  │
      │                                            │
      └────────────────────────────────────────────┘
      
      #{current_settings}
      
      Выбери опцию: 
    MENU
  end

  def format_current_settings
    settings = []
    settings << "Длина: #{@generator.length}"
    
    types = []
    types << "строчные" if @generator.include_lowercase
    types << "ЗАГЛАВНЫЕ" if @generator.include_uppercase
    types << "123цифры" if @generator.include_digits
    types << "!@#спец" if @generator.include_special
    
    settings << "Типы: #{types.join(', ')}"
    settings << "Только читаемые" if @generator.readable_only
    settings << "Мин. спец: #{@generator.min_special}" if @generator.include_special
    settings << "Мин. цифр: #{@generator.min_digits}" if @generator.include_digits
    
    "📋 Текущие настройки: #{settings.join(' | ')}"
  end

  def handle_choice(choice)
    case choice
    when '1'
      generate_single_password
    when '2'
      generate_multiple_passwords
    when '3'
      settings_menu
    when '4'
      check_password_strength
    when '5'
      show_examples
    when '6'
      export_passwords
    when '0'
      @running = false
    else
      puts "❌ Неверный выбор! Попробуй ещё раз."
    end
  end

  def generate_single_password
    begin
      password = @generator.generate
      evaluation = @generator.evaluate_strength(password)
      
      puts "\n🎉 Сгенерированный пароль:"
      puts "┌#{'─' * (password.length + 2)}┐"
      puts "│ #{password} │"
      puts "└#{'─' * (password.length + 2)}┘"
      
      puts "\n📊 Анализ силы:"
      puts "#{evaluation[:strength][:emoji]} #{evaluation[:strength][:level]} (#{evaluation[:score]}/11 баллов)"
      
      evaluation[:feedback].each { |fb| puts "   #{fb}" }
      
      puts "\n💡 Хочешь скопировать пароль? (введи 'copy' или нажми Enter)"
      input = gets.chomp.downcase
      
      if input == 'copy'
        copy_to_clipboard(password)
      end
      
    rescue => e
      puts "❌ #{e.message}"
    end
  end

  def generate_multiple_passwords
    print "\n🔢 Сколько паролей сгенерировать? (1-20): "
    count = gets.chomp.to_i
    
    if count < 1 || count > 20
      puts "❌ Количество должно быть от 1 до 20!"
      return
    end
    
    begin
      passwords = @generator.generate_multiple(count)
      
      puts "\n🎉 Сгенерированные пароли:"
      puts "═" * 50
      
      passwords.each_with_index do |password, index|
        evaluation = @generator.evaluate_strength(password)
        strength_indicator = evaluation[:strength][:emoji]
        
        puts "#{index + 1}.".rjust(3) + " #{password} #{strength_indicator}"
      end
      
      puts "═" * 50
      puts "💾 Хочешь экспортировать пароли в файл? (да/нет): "
      
      if gets.chomp.downcase == 'да'
        export_passwords_to_file(passwords)
      end
      
    rescue => e
      puts "❌ #{e.message}"
    end
  end

  def settings_menu
    loop do
      puts <<~SETTINGS
        
        ⚙️  НАСТРОЙКИ ГЕНЕРАТОРА
        ════════════════════════
        
        1. Длина пароля: #{@generator.length}
        2. Строчные буквы (a-z): #{status_icon(@generator.include_lowercase)}
        3. Заглавные буквы (A-Z): #{status_icon(@generator.include_uppercase)}
        4. Цифры (0-9): #{status_icon(@generator.include_digits)}
        5. Спецсимволы (!@#$%): #{status_icon(@generator.include_special)}
        6. Только читаемые символы: #{status_icon(@generator.readable_only)}
        7. Исключить двусмысленные (0,O,l,1,I): #{status_icon(@generator.exclude_ambiguous)}
        8. Мин. количество спецсимволов: #{@generator.min_special}
        9. Мин. количество цифр: #{@generator.min_digits}
        0. Вернуться в главное меню
        
        Выбери настройку для изменения: 
      SETTINGS
      
      choice = gets.chomp
      
      case choice
      when '1'
        change_length
      when '2'
        @generator.include_lowercase = !@generator.include_lowercase
      when '3'
        @generator.include_uppercase = !@generator.include_uppercase
      when '4'
        @generator.include_digits = !@generator.include_digits
      when '5'
        @generator.include_special = !@generator.include_special
      when '6'
        @generator.readable_only = !@generator.readable_only
      when '7'
        @generator.exclude_ambiguous = !@generator.exclude_ambiguous
      when '8'
        change_min_special
      when '9'
        change_min_digits
      when '0'
        break
      else
        puts "❌ Неверный выбор!"
      end
    end
  end

  def change_length
    print "\n📏 Введи новую длину пароля (4-128): "
    length = gets.chomp.to_i
    
    if length >= 4 && length <= 128
      @generator.length = length
      puts "✅ Длина изменена на #{length}"
    else
      puts "❌ Длина должна быть от 4 до 128 символов!"
    end
  end

  def change_min_special
    print "\n🔣 Минимальное количество спецсимволов (0-10): "
    min_special = gets.chomp.to_i
    
    if min_special >= 0 && min_special <= 10 && min_special <= @generator.length
      @generator.min_special = min_special
      puts "✅ Минимум спецсимволов: #{min_special}"
    else
      puts "❌ Значение должно быть от 0 до 10 и не больше длины пароля!"
    end
  end

  def change_min_digits
    print "\n🔢 Минимальное количество цифр (0-10): "
    min_digits = gets.chomp.to_i
    
    if min_digits >= 0 && min_digits <= 10 && min_digits <= @generator.length
      @generator.min_digits = min_digits
      puts "✅ Минимум цифр: #{min_digits}"
    else
      puts "❌ Значение должно быть от 0 до 10 и не больше длины пароля!"
    end
  end

  def check_password_strength
    print "\n🔍 Введи пароль для проверки: "
    password = gets.chomp
    
    if password.empty?
      puts "❌ Пароль не может быть пустым!"
      return
    end
    
    evaluation = @generator.evaluate_strength(password)
    
    puts "\n📊 АНАЛИЗ ПАРОЛЯ"
    puts "═" * 40
    puts "Пароль: #{password}"
    puts "Длина: #{password.length} символов"
    puts "Оценка: #{evaluation[:strength][:emoji]} #{evaluation[:strength][:level]}"
    puts "Баллы: #{evaluation[:score]}/11"
    puts "\n📋 Детальный анализ:"
    evaluation[:feedback].each { |fb| puts "   #{fb}" }
    puts "═" * 40
  end

  def show_examples
    puts <<~EXAMPLES
      
      💡 ПРИМЕРЫ ПАРОЛЕЙ
      ═══════════════════
      
      🔹 Простой (только буквы и цифры):
         AbC123XyZ789
      
      🔹 Средний (с некоторыми спецсимволами):
         MyP@ssw0rd2024!
      
      🔹 Сложный (все типы символов):
         X7#mK9$nR2@vL4&
      
      🔹 Очень сложный (длинный с разнообразием):
         aB3$fG7!jK2@nM8%qR5^tY9*
      
      🔹 Читаемый (без похожих символов):
         BigHouse23!Jump
      
      🔹 Для корпоративных систем:
         TechCorp2024#Secure!
      
      💡 Рекомендации:
      • Минимум 12 символов для обычного использования
      • Минимум 16 символов для важных аккаунтов
      • Используй все типы символов
      • Избегай словарных слов и личных данных
      • Используй уникальный пароль для каждого сервиса
      
    EXAMPLES
  end

  def export_passwords
    print "\n🔢 Сколько паролей экспортировать? (1-50): "
    count = gets.chomp.to_i
    
    if count < 1 || count > 50
      puts "❌ Количество должно быть от 1 до 50!"
      return
    end
    
    begin
      passwords = @generator.generate_multiple(count)
      export_passwords_to_file(passwords)
    rescue => e
      puts "❌ #{e.message}"
    end
  end

  def export_passwords_to_file(passwords)
    filename = "passwords_#{Time.now.strftime('%Y%m%d_%H%M%S')}.txt"
    
    File.open(filename, 'w') do |file|
      file.puts "# Сгенерированные пароли"
      file.puts "# Дата: #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"
      file.puts "# Настройки: длина=#{@generator.length}, типы=#{format_types}"
      file.puts "#" + "=" * 50
      file.puts
      
      passwords.each_with_index do |password, index|
        evaluation = @generator.evaluate_strength(password)
        file.puts "#{index + 1}. #{password} (#{evaluation[:strength][:level]})"
      end
    end
    
    puts "✅ Пароли экспортированы в файл: #{filename}"
  end

  def copy_to_clipboard(text)
    # Попытка скопировать в буфер обмена (зависит от ОС)
    begin
      if RUBY_PLATFORM.match?(/darwin/) # macOS
        `echo "#{text}" | pbcopy`
        puts "✅ Пароль скопирован в буфер обмена!"
      elsif RUBY_PLATFORM.match?(/linux/) # Linux
        `echo "#{text}" | xclip -selection clipboard 2>/dev/null || echo "#{text}" | xsel --clipboard 2>/dev/null`
        puts "✅ Пароль скопирован в буфер обмена!"
      else
        puts "📋 Скопируй пароль вручную: #{text}"
      end
    rescue
      puts "📋 Автокопирование недоступно. Скопируй пароль вручную: #{text}"
    end
  end

  def status_icon(enabled)
    enabled ? "✅ включено" : "❌ выключено"
  end

  def format_types
    types = []
    types << "строчные" if @generator.include_lowercase
    types << "заглавные" if @generator.include_uppercase
    types << "цифры" if @generator.include_digits
    types << "спецсимволы" if @generator.include_special
    types.join(', ')
  end

  def get_user_input
    print "➤ "
    gets.chomp
  end
end

# Запуск программы
if __FILE__ == $0
  begin
    app = PasswordGeneratorUI.new
    app.start
  rescue Interrupt
    puts "\n\n👋 Программа завершена пользователем."
  rescue => e
    puts "\n❌ Произошла ошибка: #{e.message}"
    puts "🐛 Если проблема повторяется, обратись к разработчику."
  end
end
