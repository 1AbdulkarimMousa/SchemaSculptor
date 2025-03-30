package util

import (
	"math/rand"
	"strconv"
	"strings"
	"time"
)

// var constant: please don't mutate it
var Street = []string{
	"Avon Close",
	"Little Lane",
	"Thomas Street",
	"West End",
	"Beech Road",
	"Sycamore Avenue",
	"Victoria Street",
	"Laurel Drive",
	"St Michael's Road",
	"Kings Road",
}

var ContactTypes = []string{
	"customer",
	"vendor",
	"billing",
	"location",
	"company",
}

const (
	Alphabet   = "abcdefghijklmnopqrstuvwxyz"
	Characters = "!@#$%^&*()_+~"
	Numbers    = "0123456789"
)

type Int int

func (i Int) Str() string {
	return strconv.Itoa(int(i))
}

func Rrndm(strings []string) string {
	k := len(strings) - 1
	return strings[RandomInt(0, k)]
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func RandomInt(min, max int) int32 {
	return int32(min + rand.Intn(max-min+1))
}

func RandomFloat() float64 {
	return rand.Float64()
}

func RandomDate() time.Time {
	t := time.Now()
	t = t.AddDate(int(RandomInt(2, 10)), int(RandomInt(1, 10)), int(RandomInt(1, 10)))
	loc := time.FixedZone("", 0)
	res := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc).Round(time.Second)
	return res
}

func RandomChar(n int) string {
	var sb strings.Builder
	k := len(Characters)

	for i := 0; i < n; i++ {
		c := Alphabet[rand.Intn(k)]
		sb.WriteByte(c)
	}
	return sb.String()
}

func RandomStr(n int) string {
	var sb strings.Builder
	k := len(Alphabet)

	for i := 0; i < n; i++ {
		c := Alphabet[rand.Intn(k)]
		sb.WriteByte(c)
	}
	return sb.String()
}

func RandomName(n int) string {
	return RandomStr(6)
}

func RandomBool() bool {
	return RandomInt(0, 1) > RandomInt(0, 1)
}

func RandomEmail() string {
	return RandomStr(6) + "@" + RandomStr(6) + ".com"
}

func RandomPassword(min, max int) string {
	var sb strings.Builder
	length := RandomInt(min, max)
	k1 := len(Alphabet)
	k2 := len(Characters)

	for i := 0; i < int(length); i++ {
		switch fun := rand.Intn(3); fun {
		case 0:
			a := Alphabet[rand.Intn(k1)]
			sb.WriteByte(a)
		case 1:
			a := Characters[rand.Intn(k2)]
			sb.WriteByte(a)
		case 2:
			a := Numbers[rand.Intn(10)]
			sb.WriteByte(a)
		}
	}
	return sb.String()
}

// func Diff(i any, r func(...any)) {
// 	r.
// 	for i != r(_) {
// 		return Diff(i )
// 	}
// }
