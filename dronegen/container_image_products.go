package main

import (
	"fmt"
	"path"
	"regexp"
)

type Product struct {
	Name                 string
	DockerfilePath       string
	WorkingDirectory     string
	DockerfileTarget     string
	SupportedArchs       []string
	SetupSteps           []step
	DockerfileArgBuilder func(arch string) []string
	ImageBuilder         func(repo string, tag *ImageTag) *Image
	GetRequiredStepNames func(arch string) []string
}

func NewTeleportOperatorProduct(cloneDirectory string) *Product {
	name := "teleport-operator"
	return &Product{
		Name:             name,
		DockerfilePath:   path.Join(cloneDirectory, "operator", "Dockerfile"),
		WorkingDirectory: cloneDirectory,
		SupportedArchs:   []string{"amd64", "arm", "arm64"},
		ImageBuilder: func(repo string, tag *ImageTag) *Image {
			return &Image{
				Repo: repo,
				Name: name,
				Tag:  tag,
			}
		},
		DockerfileArgBuilder: func(arch string) []string {
			gccPackage := ""
			compilerName := ""
			switch arch {
			case "x86_64", "amd64":
				gccPackage = "gcc-x86-64-linux-gnu"
				compilerName = "x86_64-linux-gnu-gcc"
			case "i686", "i386":
				gccPackage = "gcc-multilib-i686-linux-gnu"
				compilerName = "i686-linux-gnu-gcc"
			case "arm64", "aarch64":
				gccPackage = "gcc-aarch64-linux-gnu"
				compilerName = "aarch64-linux-gnu-gcc"
			// We may want to add additional arm ISAs in the future to support devices without hardware FPUs
			case "armhf":
			case "arm":
				gccPackage = "gcc-arm-linux-gnueabihf"
				compilerName = "arm-linux-gnueabihf-gcc"
			}

			return []string{
				fmt.Sprintf("COMPILER_PACKAGE=%s", gccPackage),
				fmt.Sprintf("COMPILER_NAME=%s", compilerName),
			}
		},
	}
}

func (p *Product) getBaseImage(arch string, version *releaseVersion) *Image {
	return &Image{
		Name: p.Name,
		Tag: &ImageTag{
			ShellBaseValue:   version.ShellVersion,
			DisplayBaseValue: version.MajorVersion,
			Arch:             arch,
		},
	}
}

func (p *Product) GetLocalRegistryImage(arch string, version *releaseVersion) *Image {
	image := p.getBaseImage(arch, version)
	image.Repo = localRegistry

	return image
}

func (p *Product) GetStagingRegistryImage(arch string, version *releaseVersion, stagingRepo *ContainerRepo) *Image {
	image := p.getBaseImage(arch, version)
	image.Repo = stagingRepo.RegistryDomain

	return image
}

func (p *Product) buildSteps(version *releaseVersion, setupStepNames []string, flags *TriggerFlags) []step {
	steps := make([]step, 0)

	stagingRepo := GetStagingContainerRepo(flags.UseUniqueStagingTag)
	productionRepos := GetProductionContainerRepos()

	for _, setupStep := range p.SetupSteps {
		setupStep.DependsOn = append(setupStep.DependsOn, setupStepNames...)
		steps = append(steps, setupStep)
		setupStepNames = append(setupStepNames, setupStep.Name)
	}

	archBuildStepDetails := make([]*buildStepOutput, 0, len(p.SupportedArchs))

	for _, supportedArch := range p.SupportedArchs {
		// Include steps for building images from scratch
		if flags.ShouldBuildNewImages {
			archBuildStep, archBuildStepDetail := p.createBuildStep(supportedArch, version)

			archBuildStep.DependsOn = append(archBuildStep.DependsOn, setupStepNames...)
			if p.GetRequiredStepNames != nil {
				archBuildStep.DependsOn = append(archBuildStep.DependsOn, p.GetRequiredStepNames(supportedArch)...)
			}

			steps = append(steps, archBuildStep)
			archBuildStepDetails = append(archBuildStepDetails, archBuildStepDetail)
		} else {
			// Generate build details that point to staging images
			archBuildStepDetails = append(archBuildStepDetails, &buildStepOutput{
				StepName:   "",
				BuiltImage: p.GetStagingRegistryImage(supportedArch, version, stagingRepo),
				Version:    version,
				Product:    p,
			})
		}
	}

	for _, containerRepo := range getReposToPublishTo(productionRepos, stagingRepo, flags) {
		steps = append(steps, containerRepo.buildSteps(archBuildStepDetails)...)
	}

	return steps
}

func getReposToPublishTo(productionRepos []*ContainerRepo, stagingRepo *ContainerRepo, flags *TriggerFlags) []*ContainerRepo {
	stagingRepos := []*ContainerRepo{stagingRepo}

	if flags.ShouldAffectProductionImages {
		if !flags.ShouldBuildNewImages {
			// In this case the images will be pulled from staging and therefor should not be re-published
			// to staging
			return productionRepos
		}

		return append(stagingRepos, productionRepos...)
	}

	return stagingRepos
}

func (p *Product) GetBuildStepName(arch string, version *releaseVersion) string {
	telportImageName := p.GetLocalRegistryImage(arch, version)
	return fmt.Sprintf("Build %s image %q", p.Name, telportImageName.GetDisplayName())
}

func cleanBuilderName(builderName string) string {
	var invalidBuildxCharExpression = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
	return invalidBuildxCharExpression.ReplaceAllString(builderName, "-")
}

func (p *Product) createBuildStep(arch string, version *releaseVersion) (step, *buildStepOutput) {
	localRegistryImage := p.GetLocalRegistryImage(arch, version)
	builderName := cleanBuilderName(fmt.Sprintf("%s-builder", localRegistryImage.GetDisplayName()))

	buildxConfigFileDir := path.Join("/tmp", builderName)
	buildxConfigFilePath := path.Join(buildxConfigFileDir, "buildkitd.toml")

	buildxCreateCommand := "docker buildx create"
	buildxCreateCommand += fmt.Sprintf(" --driver %q", "docker-container")
	// This is set so that buildx can reach the local registry
	buildxCreateCommand += fmt.Sprintf(" --driver-opt %q", "network=host")
	buildxCreateCommand += fmt.Sprintf(" --name %q", builderName)
	buildxCreateCommand += fmt.Sprintf(" --config %q", buildxConfigFilePath)

	buildCommand := "docker buildx build"
	buildCommand += " --push"
	buildCommand += fmt.Sprintf(" --builder %q", builderName)
	if p.DockerfileTarget != "" {
		buildCommand += fmt.Sprintf(" --target %q", p.DockerfileTarget)
	}
	buildCommand += fmt.Sprintf(" --platform %q", "linux/"+arch)
	buildCommand += fmt.Sprintf(" --tag %q", localRegistryImage.GetShellName())
	buildCommand += fmt.Sprintf(" --file %q", p.DockerfilePath)
	if p.DockerfileArgBuilder != nil {
		for _, buildArg := range p.DockerfileArgBuilder(arch) {
			buildCommand += fmt.Sprintf(" --build-arg %q", buildArg)
		}
	}
	buildCommand += " " + p.WorkingDirectory

	step := step{
		Name:    p.GetBuildStepName(arch, version),
		Image:   "docker",
		Volumes: dockerVolumeRefs(),
		Environment: map[string]value{
			"DOCKER_BUILDKIT": {
				raw: "1",
			},
		},
		Commands: []string{
			"docker run --privileged --rm tonistiigi/binfmt --install all",
			fmt.Sprintf("mkdir -pv %q && cd %q", p.WorkingDirectory, p.WorkingDirectory),
			fmt.Sprintf("mkdir -pv %q", buildxConfigFileDir),
			fmt.Sprintf("echo '[registry.%q]' > %q", localRegistry, buildxConfigFilePath),
			fmt.Sprintf("echo '  http = true' >> %q", buildxConfigFilePath),
			buildxCreateCommand,
			buildCommand,
			fmt.Sprintf("docker buildx rm %q", builderName),
			fmt.Sprintf("rm -rf %q", buildxConfigFileDir),
		},
	}

	return step, &buildStepOutput{
		StepName:   step.Name,
		BuiltImage: localRegistryImage,
		Version:    version,
		Product:    p,
	}
}
