export GOPATH=$PWD
export GOBIN=$GOPATH/bin
export PATH=$PATH:$GOBIN

# Now you can go inside the src folder in the current directory and compile
# the code with: 
# $ go install source_code.go
# Then you can directly execute it by:
# $ source_code
# To test the library, go to the library directory and:
# $ go test
