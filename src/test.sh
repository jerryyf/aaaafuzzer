# # custom test binaries

./fuzzer ../assets/test_binaries/testjson1 ../assets/json1.txt
./fuzzer ../assets/test_binaries/testjson2 ../assets/json1.txt
./fuzzer ../assets/test_binaries/testjson3 ../assets/json1.txt
./fuzzer ../assets/test_binaries/testjson4 ../assets/json1.txt
./fuzzer ../assets/test_binaries/testjson5 ../assets/json1.txt

# test against provided binaries and sample inputs

./fuzzer ../assets/json1 ../assets/json1.txt
./fuzzer ../assets/json2 ../assets/json2.txt
./fuzzer ../assets/csv1 ../assets/csv1.txt
./fuzzer ../assets/csv2 ../assets/csv2.txt

./fuzzer ../assets/plaintext1 ../assets/plaintext1.txt
./fuzzer ../assets/plaintext2 ../assets/plaintext2.txt
./fuzzer ../assets/plaintext3 ../assets/plaintext3.txt

./fuzzer ../assets/xml1 ../assets/xml1.txt
./fuzzer ../assets/xml2 ../assets/xml2.txt
./fuzzer ../assets/xml3 ../assets/xml3.txt

./fuzzer ../assets/jpg1 ../assets/jpg1.txt
