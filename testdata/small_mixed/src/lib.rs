pub fn double(x: i32) -> i32 {
    x * 2
}

pub fn quadruple(x: i32) -> i32 {
    double(double(x))
}
