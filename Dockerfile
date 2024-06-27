FROM rust:latest

WORKDIR /usr/src/password-cracker-v1

COPY . . 

RUN cargo build

CMD cargo run