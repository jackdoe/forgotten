package main

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
)

const (
	// LowerLetters is the list of lowercase letters.
	LowerLetters = "abcdefghijklmnopqrstuvwxyz"

	// UpperLetters is the list of uppercase letters.
	UpperLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	// Digits is the list of permitted digits.
	Digits = "0123456789"

	// Symbols is the list of symbols.
	Symbols = "~!@#$%^&*()_+`-={}|[]\\:\"<>?,./"
)

var (
	// ErrExceedsTotalLength is the error returned with the number of digits and
	// symbols is greater than the total length.
	ErrExceedsTotalLength = errors.New("number of digits and symbols must be less than total length")

	// ErrLettersExceedsAvailable is the error returned with the number of letters
	// exceeds the number of available letters and repeats are not allowed.
	ErrLettersExceedsAvailable = errors.New("number of letters exceeds available letters and repeats are not allowed")

	// ErrDigitsExceedsAvailable is the error returned with the number of digits
	// exceeds the number of available digits and repeats are not allowed.
	ErrDigitsExceedsAvailable = errors.New("number of digits exceeds available digits and repeats are not allowed")

	// ErrSymbolsExceedsAvailable is the error returned with the number of symbols
	// exceeds the number of available symbols and repeats are not allowed.
	ErrSymbolsExceedsAvailable = errors.New("number of symbols exceeds available symbols and repeats are not allowed")
)

// Generator is the stateful generator which can be used to customize the list
// of letters, digits, and/or symbols.
type Generator struct {
	lowerLetters string
	upperLetters string
	digits       string
	symbols      string
}

// GeneratorInput is used as input to the NewGenerator function.
type GeneratorInput struct {
	LowerLetters string
	UpperLetters string
	Digits       string
	Symbols      string
}

// NewGenerator creates a new Generator from the specified configuration. If no
// input is given, all the default values are used. This function is safe for
// concurrent use.
func NewGenerator(i *GeneratorInput) (*Generator, error) {
	if i == nil {
		i = new(GeneratorInput)
	}

	g := &Generator{
		lowerLetters: i.LowerLetters,
		upperLetters: i.UpperLetters,
		digits:       i.Digits,
		symbols:      i.Symbols,
	}

	if g.lowerLetters == "" {
		g.lowerLetters = LowerLetters
	}

	if g.upperLetters == "" {
		g.upperLetters = UpperLetters
	}

	if g.digits == "" {
		g.digits = Digits
	}

	if g.symbols == "" {
		g.symbols = Symbols
	}

	return g, nil
}

// Generate generates a password with the given requirements. length is the
// total number of characters in the password. numDigits is the number of digits
// to include in the result. numSymbols is the number of symbols to include in
// the result. noUpper excludes uppercase letters from the results. allowRepeat
// allows characters to repeat.
//
// The algorithm is fast, but it's not designed to be performant; it favors
// entropy over speed. This function is safe for concurrent use.
func (g *Generator) Generate(length, numDigits, numSymbols int, noUpper, allowRepeat bool) (string, error) {
	letters := g.lowerLetters
	if !noUpper {
		letters += g.upperLetters
	}

	chars := length - numDigits - numSymbols
	if chars < 0 {
		return "", ErrExceedsTotalLength
	}

	if !allowRepeat && chars > len(letters) {
		return "", ErrLettersExceedsAvailable
	}

	if !allowRepeat && numDigits > len(g.digits) {
		return "", ErrDigitsExceedsAvailable
	}

	if !allowRepeat && numSymbols > len(g.symbols) {
		return "", ErrSymbolsExceedsAvailable
	}

	var result string

	// Characters
	for i := 0; i < chars; i++ {
		ch, err := randomElement(letters)
		if err != nil {
			return "", err
		}

		if !allowRepeat && strings.Contains(result, ch) {
			i--
			continue
		}

		result, err = randomInsert(result, ch)
		if err != nil {
			return "", err
		}
	}

	// Digits
	for i := 0; i < numDigits; i++ {
		d, err := randomElement(g.digits)
		if err != nil {
			return "", err
		}

		if !allowRepeat && strings.Contains(result, d) {
			i--
			continue
		}

		result, err = randomInsert(result, d)
		if err != nil {
			return "", err
		}
	}

	// Symbols
	for i := 0; i < numSymbols; i++ {
		sym, err := randomElement(g.symbols)
		if err != nil {
			return "", err
		}

		if !allowRepeat && strings.Contains(result, sym) {
			i--
			continue
		}

		result, err = randomInsert(result, sym)
		if err != nil {
			return "", err
		}
	}

	return result, nil
}

// MustGenerate is the same as Generate, but panics on error.
func (g *Generator) MustGenerate(length, numDigits, numSymbols int, noUpper, allowRepeat bool) string {
	res, err := g.Generate(length, numDigits, numSymbols, noUpper, allowRepeat)
	if err != nil {
		panic(err)
	}
	return res
}

// Generate is the package shortcut for Generator.Generate.
func Generate(length, numDigits, numSymbols int, noUpper, allowRepeat bool) (string, error) {
	gen, err := NewGenerator(nil)
	if err != nil {
		return "", err
	}

	return gen.Generate(length, numDigits, numSymbols, noUpper, allowRepeat)
}

// MustGenerate is the package shortcut for Generator.MustGenerate.
func MustGenerate(length, numDigits, numSymbols int, noUpper, allowRepeat bool) string {
	res, err := Generate(length, numDigits, numSymbols, noUpper, allowRepeat)
	if err != nil {
		panic(err)
	}
	return res
}

// randomInsert randomly inserts the given value into the given string.
func randomInsert(s, val string) (string, error) {
	if s == "" {
		return val, nil
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(s)+1)))
	if err != nil {
		return "", err
	}
	i := n.Int64()
	return s[0:i] + val + s[i:len(s)], nil
}

// randomElement extracts a random element from the given string.
func randomElement(s string) (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(s))))
	if err != nil {
		return "", err
	}
	return string(s[n.Int64()]), nil
}
