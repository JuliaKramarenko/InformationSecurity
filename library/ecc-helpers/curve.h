#ifndef AES_KALYNA_CURVE_H
#define AES_KALYNA_CURVE_H

#include <cstdint>
#include <gmpxx.h>

class Point
{
 private:

  mpz_class _x, _y;

 public:
  Point();
  Point(mpz_class x, mpz_class y);

  mpz_class getX();
  mpz_class getY();

  void setX(mpz_class x);
  void setY(mpz_class y);

  const Point& operator = (const Point& other);
  const bool operator==(const Point& rhs) const;

  friend std::ostream& operator << (std::ostream& os, const Point& number);

  ~Point();
};

class EllipticCurve {
 private:
  mpz_class _A, _B, _f, _m, _mask;
  Point _zero;

 public:
  Point getZero(){return _zero;}
  mpz_class getF() const {return _f;}
  mpz_class getM() const {return _m;}
  mpz_class getMask() const {return _mask;}

  EllipticCurve(mpz_class A, mpz_class B, mpz_class m, mpz_class f);

  Point AddPoints(Point p1, Point q1);

  Point DoublePoint(Point p);

  static Point NegPoint(Point point);

  Point MultPoint(Point point, mpz_class d);

  bool PointOnCurve(Point point);

  Point GenPoint();

  mpz_class RandFieldElement();

  std::pair<mpz_class, mpz_class> SolveQuadEq(mpz_class u, mpz_class w);
};

#endif //AES_KALYNA_CURVE_H
