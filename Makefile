SHELL := /bin/bash
.SHELLFLAGS := -e -o pipefail -c
.DEFAULT_GOAL := help
SHA := $(shell git rev-parse HEAD)

.PHONY: help check lint fmt fmt-check validate vet test image-oci image-push plan apply output deploy

help:
	@echo 'make check                    lint + test'
	@echo 'make lint                     fmt-check + validate + go vet/gofmt'
	@echo 'make fmt                      Format Terraform and Terragrunt'
	@echo 'make validate                 terraform validate + terragrunt hcl validate'
	@echo 'make test                     go test'
	@echo 'make image-oci                Build linux/amd64 OCI archive (dist/image.tar)'
	@echo 'make image-push ENV=dev       Build and push to ECR, print digest'
	@echo 'make plan ENV=dev             Save a Terragrunt plan in dist/plans/'
	@echo 'make apply ENV=dev            Apply that saved plan'
	@echo 'make output ENV=dev           terragrunt output'
	@echo 'make deploy ENV=dev           image-push + plan + apply'

check: lint test

lint: fmt-check validate vet

fmt:
	terraform fmt -recursive terraform
	cd terraform && terragrunt hcl fmt

fmt-check:
	terraform fmt -check -recursive terraform
	cd terraform && terragrunt hcl fmt --check

validate:
	terraform -chdir=terraform init -backend=false -input=false
	terraform -chdir=terraform validate
	cd terraform/environments/dev && terragrunt hcl validate
	cd terraform/environments/prod && terragrunt hcl validate

vet:
	cd code && go vet ./... && test -z "$$(gofmt -l .)"

test:
	cd code && go test ./...

image-oci:
	mkdir -p dist
	rm -f dist/image.tar
	docker buildx build --platform linux/amd64 --target lambda --provenance=false --sbom=false \
		--output type=oci,dest=dist/image.tar -t soar-api:git-$(SHA) .

image-push:
	aws ecr get-login-password --region $${TG_AWS_REGION:-ap-southeast-2} | \
		docker login --username AWS --password-stdin $${TG_ECR_REPOSITORY_URL%%/*}
	docker buildx build --platform linux/amd64 --target lambda --provenance=false --sbom=false \
		-t $$TG_ECR_REPOSITORY_URL:git-$(SHA) --push .
	@aws ecr describe-images --region $${TG_AWS_REGION:-ap-southeast-2} \
		--repository-name $${TG_ECR_REPOSITORY_URL#*/} --image-ids imageTag=git-$(SHA) \
		--query 'imageDetails[0].imageDigest' --output text

plan:
	mkdir -p dist/plans
	rm -f dist/plans/$(ENV).tfplan
	cd terraform/environments/$(ENV) && terragrunt run -- plan -input=false -lock-timeout=5m -out=$(CURDIR)/dist/plans/$(ENV).tfplan

apply:
	cd terraform/environments/$(ENV) && terragrunt run -- apply -input=false -lock-timeout=5m $(CURDIR)/dist/plans/$(ENV).tfplan

output:
	cd terraform/environments/$(ENV) && terragrunt run -- output

deploy:
	$(MAKE) image-push ENV=$(ENV)
	TG_IMAGE_DIGEST=$$(aws ecr describe-images --region $${TG_AWS_REGION:-ap-southeast-2} \
		--repository-name $${TG_ECR_REPOSITORY_URL#*/} --image-ids imageTag=git-$(SHA) \
		--query 'imageDetails[0].imageDigest' --output text) $(MAKE) plan ENV=$(ENV)
	$(MAKE) apply ENV=$(ENV)
