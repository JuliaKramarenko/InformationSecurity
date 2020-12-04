#include "curve.h"
#include <iostream>
#include <cassert>
#include "../rsa-helpers/helpers.h"
#include "gf2.h"
#include "transformations.h"
#include <cmath>

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

EllipticCurve::EllipticCurve(mpz_class A, mpz_class B, unsigned int m, std::vector<mpz_class> powers){
  assert(BitLength(A) <= m);
  assert(BitLength(B) <= m);
  mpz_init_set(_A.get_mpz_t(), A.get_mpz_t());
  mpz_init_set(_B.get_mpz_t(), B.get_mpz_t());
  _m = m;

  mpz_init_set(_f.get_mpz_t(),GF::ConvertToFx(powers).get_mpz_t());
  assert(BitLength(_f) <= m+1);

  _zero = Point(0,0);
  mpz_init_set(_mask.get_mpz_t() , mpz_class((mpz_class(1) << _m) - mpz_class(1)).get_mpz_t());
}
Point EllipticCurve::AddPoints(Point p1, Point q1){
  if (p1 == _zero)
    return q1;
  if (q1 == _zero)
    return p1;
  if (p1.getX() == q1.getX() && p1.getY() != q1.getY()) // p1 + -p1 == 0
    return _zero;
  if (p1.getX() == q1.getX()) // p1 == p2
    return DoublePoint(p1);
  else {
    mpz_class temp(0), Lambda(0), x(0), y(0);
    //Lambda
    mpz_set(Lambda.get_mpz_t(), GF::Add(p1.getY(), q1.getY()).get_mpz_t()); //p1.Y + q1.Y
    mpz_set(temp.get_mpz_t(), GF::Add(p1.getX(), q1.getX()).get_mpz_t()); //p1.X + q1.X
    mpz_set(Lambda.get_mpz_t(), GF::Div(Lambda, temp, _f).get_mpz_t()); // (p1.Y + q1.Y) / (p1.X + q1.X)) (f)
    //x
    mpz_set(x.get_mpz_t(), GF::Add(GF::Add(GF::Add(GF::Add(GF::Square(Lambda, _f), Lambda), p1.getX()), q1.getX()), _A).get_mpz_t());
    //y
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
  mpz_class one(1);
  mpz_class two(2);
  while (d > 0) {
    if (d % two == one) {
      result = AddPoints(result, addend);
    }
    addend = DoublePoint(addend);
    mpz_div(d.get_mpz_t(), d.get_mpz_t(), two.get_mpz_t()); // d/=2
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
#if DEBUG
    printf("\nGenPoint \nu = ");
        mpz_out_str(stdout, 10, u.get_mpz_t());
        printf("\n------------------------------------------------------------------------------------------\n");
        printf("\nf = ");
        mpz_out_str(stdout, 10, _f.get_mpz_t());
        printf("\n------------------------------------------------------------------------------------------\n");
#endif
    mpz_class temp(0);
    mpz_set(w.get_mpz_t(),GF::Square(u, _f).get_mpz_t()); // u*u (f)
    mpz_set(w.get_mpz_t(), GF::Mult(w, _A, _f).get_mpz_t()); // (A * u*u (f))(f)
    mpz_set(temp.get_mpz_t(), GF::ModPow(u, 3, _f).get_mpz_t()); // u^3 (f)
    mpz_set(w.get_mpz_t(), GF::Add(w, temp).get_mpz_t());// u^3 (f) + (A * u*u (f))(f)
    mpz_set(w.get_mpz_t(), GF::Add(w, _B).get_mpz_t());// w = u^3 (f) + (A * u*u (f))(f) + B

    auto  [s1, s2] = SolveQuadEq(u, w);
    if (s2 == 2)
      return Point(u, s1);
  }
}

mpz_class EllipticCurve::RandFieldElement(){
  unsigned int length  = std::ceil(_m/8.f);
  mpz_class rand(0);
  mpz_random(rand.get_mpz_t(), length);
  mpz_class res(0);
  mpz_and(res.get_mpz_t(), rand.get_mpz_t(), _mask.get_mpz_t());
#if DEBUG
  printf("\nrand = ");
    mpz_out_str(stdout, 10, rand.get_mpz_t());
    printf("\n------------------------------------------------------------------------------------------\n");
    printf("\nmask = ");
    mpz_out_str(stdout, 10, _mask.get_mpz_t());
    printf("\n------------------------------------------------------------------------------------------\n");
#endif //DEBUG
  return res;
}

std::pair<mpz_class, mpz_class> EllipticCurve::SolveQuadEq(mpz_class u, mpz_class w){
  if (u == 0)
    return std::pair(GF::Sqrt(w, _f), 2);
  else if ( w == 0)
    return std::pair(0, 2);

  mpz_class u_square(0), v(0), v_trace(0);
  mpz_set(u_square.get_mpz_t(), GF::Square(u, _f).get_mpz_t());
  mpz_set(v.get_mpz_t(), GF::Div(w, u_square, _f).get_mpz_t());
  mpz_init_set(v_trace.get_mpz_t(), GF::Trace(v, _m, _f).get_mpz_t());
#if DEBUG
  printf("\nu_square = ");
    mpz_out_str(stdout, 10, u_square.get_mpz_t());
    printf("\n------------------------------------------------------------------------------------------\n");
    printf("\nv = ");
    mpz_out_str(stdout, 10, v.get_mpz_t());
    printf("\n------------------------------------------------------------------------------------------\n");
    printf("\nv_trace = ");
    mpz_out_str(stdout, 10, v_trace.get_mpz_t());
    printf("\n------------------------------------------------------------------------------------------\n");
#endif //DEBUG
  if (v_trace == 1)
    return std::pair(0, 0);

  mpz_class t, z;
  mpz_init_set(t.get_mpz_t(), GF::HalfTrace(v, _m, _f).get_mpz_t());
  mpz_init_set(z.get_mpz_t(), GF::Mult(t, u, _f).get_mpz_t());
  return std::pair(z, 2);
}