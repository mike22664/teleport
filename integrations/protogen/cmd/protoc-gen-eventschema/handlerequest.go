/*
Copyright 2022 Gravitational, Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"github.com/gogo/protobuf/protoc-gen-gogo/generator"
	gogoplugin "github.com/gogo/protobuf/protoc-gen-gogo/plugin"
	"github.com/gogo/protobuf/vanity/command"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/integrations/protogen/pkg/eventschema"
	"github.com/gravitational/teleport/integrations/protogen/pkg/tree"
)

func handleRequest(req *gogoplugin.CodeGeneratorRequest) error {
	if len(req.FileToGenerate) == 0 {
		return trace.Errorf("no input file provided")
	}
	if len(req.FileToGenerate) > 1 {
		return trace.Errorf("too many input files")
	}

	gen, err := newGenerator(req)
	if err != nil {
		return trace.Wrap(err)
	}

	rootFileName := req.FileToGenerate[0]
	gen.SetFile(rootFileName)
	for _, fileDesc := range gen.AllFiles().File {
		file := gen.AddFile(fileDesc)
		if fileDesc.GetName() == rootFileName {
			if err := generateSchema(file, gen.Response); err != nil {
				return trace.Wrap(err)
			}
		}
	}

	command.Write(gen.Response)

	return nil
}

func newGenerator(req *gogoplugin.CodeGeneratorRequest) (*tree.Forest, error) {
	gen := generator.New()

	gen.Request = req
	gen.CommandLineParameters(gen.Request.GetParameter())
	gen.WrapTypes()
	gen.SetPackageNames()
	gen.BuildTypeNameMap()

	return tree.NewForest(gen), nil
}

func generateSchema(file *tree.File, resp *gogoplugin.CodeGeneratorResponse) error {
	gen := eventschema.NewSchemaGenerator()

	err := gen.Process(file)
	if err != nil {
		return trace.Wrap(err)
	}

	name := "zz_generated.eventschema.go"
	content, err := gen.Render()
	if err != nil {
		return trace.Wrap(err)
	}
	resp.File = append(resp.File, &gogoplugin.CodeGeneratorResponse_File{Name: &name, Content: &content})

	return nil
}
