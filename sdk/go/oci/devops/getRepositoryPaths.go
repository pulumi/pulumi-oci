// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package devops

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Repository Paths in Oracle Cloud Infrastructure Devops service.
//
// Retrieves a list of files and directories in a repository.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/devops"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := devops.GetRepositoryPaths(ctx, &devops.GetRepositoryPathsArgs{
//				RepositoryId:   testRepository.Id,
//				DisplayName:    pulumi.StringRef(repositoryPathDisplayName),
//				FolderPath:     pulumi.StringRef(repositoryPathFolderPath),
//				PathsInSubtree: pulumi.BoolRef(repositoryPathPathsInSubtree),
//				Ref:            pulumi.StringRef(repositoryPathRef),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetRepositoryPaths(ctx *pulumi.Context, args *GetRepositoryPathsArgs, opts ...pulumi.InvokeOption) (*GetRepositoryPathsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetRepositoryPathsResult
	err := ctx.Invoke("oci:DevOps/getRepositoryPaths:getRepositoryPaths", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getRepositoryPaths.
type GetRepositoryPathsArgs struct {
	// A filter to return only resources that match the entire display name given.
	DisplayName *string                    `pulumi:"displayName"`
	Filters     []GetRepositoryPathsFilter `pulumi:"filters"`
	// The fully qualified path to the folder whose contents are returned, including the folder name. For example, /examples is a fully-qualified path to a folder named examples that was created off of the root directory (/) of a repository.
	FolderPath *string `pulumi:"folderPath"`
	// Flag to determine if files must be retrived recursively. Flag is False by default.
	PathsInSubtree *bool `pulumi:"pathsInSubtree"`
	// The name of branch/tag or commit hash it points to. If names conflict, order of preference is commit > branch > tag. You can disambiguate with "heads/foobar" and "tags/foobar". If left blank repository's default branch will be used.
	Ref *string `pulumi:"ref"`
	// Unique repository identifier.
	RepositoryId string `pulumi:"repositoryId"`
}

// A collection of values returned by getRepositoryPaths.
type GetRepositoryPathsResult struct {
	DisplayName *string                    `pulumi:"displayName"`
	Filters     []GetRepositoryPathsFilter `pulumi:"filters"`
	FolderPath  *string                    `pulumi:"folderPath"`
	// The provider-assigned unique ID for this managed resource.
	Id             string  `pulumi:"id"`
	PathsInSubtree *bool   `pulumi:"pathsInSubtree"`
	Ref            *string `pulumi:"ref"`
	RepositoryId   string  `pulumi:"repositoryId"`
	// The list of repository_path_collection.
	RepositoryPathCollections []GetRepositoryPathsRepositoryPathCollection `pulumi:"repositoryPathCollections"`
}

func GetRepositoryPathsOutput(ctx *pulumi.Context, args GetRepositoryPathsOutputArgs, opts ...pulumi.InvokeOption) GetRepositoryPathsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetRepositoryPathsResultOutput, error) {
			args := v.(GetRepositoryPathsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DevOps/getRepositoryPaths:getRepositoryPaths", args, GetRepositoryPathsResultOutput{}, options).(GetRepositoryPathsResultOutput), nil
		}).(GetRepositoryPathsResultOutput)
}

// A collection of arguments for invoking getRepositoryPaths.
type GetRepositoryPathsOutputArgs struct {
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput              `pulumi:"displayName"`
	Filters     GetRepositoryPathsFilterArrayInput `pulumi:"filters"`
	// The fully qualified path to the folder whose contents are returned, including the folder name. For example, /examples is a fully-qualified path to a folder named examples that was created off of the root directory (/) of a repository.
	FolderPath pulumi.StringPtrInput `pulumi:"folderPath"`
	// Flag to determine if files must be retrived recursively. Flag is False by default.
	PathsInSubtree pulumi.BoolPtrInput `pulumi:"pathsInSubtree"`
	// The name of branch/tag or commit hash it points to. If names conflict, order of preference is commit > branch > tag. You can disambiguate with "heads/foobar" and "tags/foobar". If left blank repository's default branch will be used.
	Ref pulumi.StringPtrInput `pulumi:"ref"`
	// Unique repository identifier.
	RepositoryId pulumi.StringInput `pulumi:"repositoryId"`
}

func (GetRepositoryPathsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRepositoryPathsArgs)(nil)).Elem()
}

// A collection of values returned by getRepositoryPaths.
type GetRepositoryPathsResultOutput struct{ *pulumi.OutputState }

func (GetRepositoryPathsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRepositoryPathsResult)(nil)).Elem()
}

func (o GetRepositoryPathsResultOutput) ToGetRepositoryPathsResultOutput() GetRepositoryPathsResultOutput {
	return o
}

func (o GetRepositoryPathsResultOutput) ToGetRepositoryPathsResultOutputWithContext(ctx context.Context) GetRepositoryPathsResultOutput {
	return o
}

func (o GetRepositoryPathsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRepositoryPathsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetRepositoryPathsResultOutput) Filters() GetRepositoryPathsFilterArrayOutput {
	return o.ApplyT(func(v GetRepositoryPathsResult) []GetRepositoryPathsFilter { return v.Filters }).(GetRepositoryPathsFilterArrayOutput)
}

func (o GetRepositoryPathsResultOutput) FolderPath() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRepositoryPathsResult) *string { return v.FolderPath }).(pulumi.StringPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetRepositoryPathsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetRepositoryPathsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetRepositoryPathsResultOutput) PathsInSubtree() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetRepositoryPathsResult) *bool { return v.PathsInSubtree }).(pulumi.BoolPtrOutput)
}

func (o GetRepositoryPathsResultOutput) Ref() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRepositoryPathsResult) *string { return v.Ref }).(pulumi.StringPtrOutput)
}

func (o GetRepositoryPathsResultOutput) RepositoryId() pulumi.StringOutput {
	return o.ApplyT(func(v GetRepositoryPathsResult) string { return v.RepositoryId }).(pulumi.StringOutput)
}

// The list of repository_path_collection.
func (o GetRepositoryPathsResultOutput) RepositoryPathCollections() GetRepositoryPathsRepositoryPathCollectionArrayOutput {
	return o.ApplyT(func(v GetRepositoryPathsResult) []GetRepositoryPathsRepositoryPathCollection {
		return v.RepositoryPathCollections
	}).(GetRepositoryPathsRepositoryPathCollectionArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetRepositoryPathsResultOutput{})
}
