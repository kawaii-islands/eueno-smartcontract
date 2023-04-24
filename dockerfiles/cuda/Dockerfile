# build image
FROM rust:slim-buster as builder

WORKDIR /porep_app
COPY . .

ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
RUN rustup toolchain install nightly
RUN apt update -y && apt install build-essential ocl-icd-opencl-dev upx -y
RUN cargo +nightly build --release --bin porep_app --features cuda
RUN upx --best --lzma target/release/porep_app

# run image
FROM debian:buster-slim
COPY --from=builder /porep_app/target/release/porep_app /usr/bin

CMD ["porep_app"]