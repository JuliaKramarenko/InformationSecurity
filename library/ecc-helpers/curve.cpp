#include "curve.h"
#include <iostream>
#include <cassert>
#include "../rsa-helpers/helpers.h"
#include "gf2.h"
#include "transformations.h"
Point::Point(){}

Point::Point(mpz_class x, mpz_class y) {
  mpz_init_set(_x.get_mpz_t(), x.get_mpz_t());
  mpz_init_set(_y.get_mpz_t(), y.get_mpz_t());
}

mpz_class Point::getX() { return _x; }
mpz_class Point::getY() { return _y; }

void Point::setX(mpz_class x) { mpz_set(_x.get_mpz_t(), x.get_mpz_t()); }
void Point::setY(mpz_class y) { mpz_set(_y.get_mpz_t(), y.get_mpz_t()); }

const Point& Point::operator = (const Point& other) {
  if (this != &other)
  {
    mpz_set(_x.get_mpz_t(), other._x.get_mpz_t());
    mpz_set(_y.get_mpz_t(), other._y.get_mpz_t());
  }
  return *this;
}

const bool Point::operator==(const Point& rhs) const {
  if ((*this)._x == rhs._x && (*this)._y == rhs._y) return true;
  return false;
}

std::ostream& operator << (std::ostream& os, const Point& p) {
  std::cout << "( " << p._x << ", " << p._y << " )";
  return os;
}

Point::~Point()
{}

EllipticCurve::EllipticCurve(mpz_class A, mpz_class B, mpz_class m, mpz_class f){
  assert(BitLength(A) <= m);
  assert(BitLength(B) <= m);
  assert(BitLength(f) <= m+1);
  mpz_init_set(_A.get_mpz_t(), A.get_mpz_t());
  mpz_init_set(_B.get_mpz_t(), B.get_mpz_t());
  mpz_init_set(_m.get_mpz_t(), m.get_mpz_t());
  mpz_init_set(_f.get_mpz_t(), f.get_mpz_t());
  _zero = Point(0,0);
  mpz_init_set(_mask.get_mpz_t() , mpz_class((1 << _m.get_ui() - 1)).get_mpz_t());
}
Point EllipticCurve::AddPoints(Point p1, Point q1){
  if (p1 == _zero)
    return q1;
  if (q1 == _zero)
    return p1;
  if (p1.getX() == q1.getY() && p1.getY() != q1.getY()) // p1 + -p1 == 0
    return _zero;
  if (p1.getX() == q1.getX()) // p1 == p2
    return DoublePoint(p1);
  else {
    mpz_class Lambda, x, y;
    mpz_init_set(Lambda.get_mpz_t(), GF::Div(GF::Add(p1.getY(), q1.getY()), GF::Add(p1.getX(), q1.getX()), _f).get_mpz_t());
    mpz_init_set(x.get_mpz_t(), GF::Add(GF::Add(GF::Add(GF::Add(GF::Square(Lambda, _f), Lambda), p1.getX()), q1.getX()), _A).get_mpz_t());
    mpz_init_set(y.get_mpz_t(), GF::Add(GF::Add(GF::Mult(GF::Add(p1.getX(), x), Lambda, _f), x), p1.getY()).get_mpz_t());
    return Point(x, y);
  }
}

Point EllipticCurve::DoublePoint(Point p){
  if (p == NegPoint(p))
    return _zero;
  else {
    mpz_class Lambda, x, y;
    mpz_init_set(Lambda.get_mpz_t(), GF::Add(p.getX(), GF::Div(p.getY(), p.getX(), _f)).get_mpz_t());
    mpz_init_set(x.get_mpz_t() , GF::Add(GF::Add(GF::Square(Lambda, _f), Lambda), _A).get_mpz_t());
    mpz_init_set(y.get_mpz_t(), GF::Add(GF::Add(GF::Square(p.getX(), _f), GF::Mult(Lambda, x, _f)), x).get_mpz_t());
    return Point(x, y);
  }
}

Point EllipticCurve::NegPoint(Point point){
  return Point(point.getX(),point.getX() ^ point.getY());
}

Point EllipticCurve::MultPoint(Point point, mpz_class d){
  Point result = Point(0, 0);
  Point addend = point;
  while (d > 0) {
    if (d % 2 == 1)
      result = AddPoints(result, addend);
    addend = DoublePoint(addend);
    d /= 2;
  }
  return result;
}

bool EllipticCurve::PointOnCurve(Point point){
  mpz_class x, y;
  mpz_init_set(x.get_mpz_t(), point.getX().get_mpz_t());
  mpz_init_set(y.get_mpz_t(), point.getY().get_mpz_t());
  assert (BitLength(x) <= _m);
  assert (BitLength(y) <= _m);
  return GF::Add(GF::ModPow(y, 2, _f), GF::Mult(x, y, _f)) ==
      ( GF::Add( GF::Add(GF::ModPow(x, 3, _f), GF::Mult(_A, GF::ModPow(x, 2, _f), _f)),_B));
}

Point EllipticCurve::GenPoint() {
  while (1) {
    mpz_class u, w;
    mpz_init_set(u.get_mpz_t(), RandFieldElement().get_mpz_t());
    mpz_init_set (w.get_mpz_t(), GF::Add(GF::Add(
        GF::ModPow(u, 3, _f),
        GF::Mult(_A, GF::Square(u, _f), _f)), _B).get_mpz_t());
    auto  [s1, s2] = SolveQuadEq(u, w);
    if (s1 == 2)
      return Point(u, s2);
  }
}

mpz_class EllipticCurve::RandFieldElement(){
  mpz_class length(0);
  mpz_cdiv_r(length.get_mpz_t(), _m.get_mpz_t(), mpz_class(8).get_mpz_t());
  return RandINT(0, _m/8) & _mask;
}

std::pair<mpz_class, mpz_class> EllipticCurve::SolveQuadEq(mpz_class u, mpz_class w){
  if (u == 0)
    return std::pair(GF::Sqrt(w, _f), 2);
  else if ( w == 0)
    return std::pair(0, 2);

  mpz_class u_square, v, v_trace;
  mpz_init_set(u_square.get_mpz_t(), GF::Square(u, _f).get_mpz_t());
  mpz_init_set(v.get_mpz_t(), GF::Div(w, u_square, _f).get_mpz_t());

  mpz_init_set(v_trace.get_mpz_t(), GF::Trace(v, _m, _f).get_mpz_t());
  if (v_trace == 1)
    return std::pair(0, 0);

  mpz_class t, z;
  mpz_init_set(t.get_mpz_t(), GF::HalfTrace(v, _m, _f).get_mpz_t());
  mpz_init_set(z.get_mpz_t(), GF::Mult(t, u, _f).get_mpz_t());
  return std::pair(z, 2);
}
