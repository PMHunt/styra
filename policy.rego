package rules

default allow = false 

# anyone can get /cars
allow {
  input.path[0] == "cars"
  input.method == "GET"
  count(input.path) <= 1
}

# only employees can get /cars/{carid}
allow {
  input.path[0] == "cars"
  input.path[1]
  count(input.path) <= 2
  input.method == "GET"
  user_is_employee
}

# only managers can create a new car
allow {
  input.path[0] == "cars"
  input.method == "POST"
  user_is_manager
}

users := [
    {"name": "alice",   "manager": "charlie", "title": "salesperson"},
    {"name": "bob", "manager": "charlie", "title": "salesperson"},
    {"name": "charlie", "manager": "dave",    "title": "manager"},
    {"name": "dave", "manager": null,      "title": "ceo"}
]

user_is_employee {
    users[_].name == input.user
}

user_is_manager {
    users[_].manager == input.user
}