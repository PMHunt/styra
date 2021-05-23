package rules

test_car_read_positive {
    in = {
       "method": "GET",
       "path": ["cars"],
       "user": "alice"
    }
    allow == true with input as in
}

test_car_read_negative  {
    in = {
       "method": "GET",
       "path": ["nonexistent"],
       "user": "alice"
    }
    allow == false with input as in
}

test_car_status_read_positive {
    in = {
       "method": "GET",
       "path": ["cars", "car18"],
       "user": "alice"
    }
    allow == true with input as in
}

test_car_status_read_negative  {
    in = {
       "method": "GET",
       "path": ["cars", "car18"],
       "user": "andy"
    }
    allow == false with input as in
}

test_car_create_negative {
    in = {
       "method": "POST",
       "path": ["cars"],
       "user": "alice"
    }
    allow == false with input as in
}

test_car_create_positive {
    in = {
       "method": "POST",
       "path": ["cars"],
       "user": "charlie"
    }
    allow == true with input as in
}