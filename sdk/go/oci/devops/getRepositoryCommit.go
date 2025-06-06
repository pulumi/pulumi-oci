// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package devops

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Repository Commit resource in Oracle Cloud Infrastructure Devops service.
//
// Retrieves a repository's commit by commit ID.
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
//			_, err := devops.GetRepositoryCommit(ctx, &devops.GetRepositoryCommitArgs{
//				CommitId:     testCommit.Id,
//				RepositoryId: testRepository.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetRepositoryCommit(ctx *pulumi.Context, args *GetRepositoryCommitArgs, opts ...pulumi.InvokeOption) (*GetRepositoryCommitResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetRepositoryCommitResult
	err := ctx.Invoke("oci:DevOps/getRepositoryCommit:getRepositoryCommit", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getRepositoryCommit.
type GetRepositoryCommitArgs struct {
	// A filter to return only resources that match the given commit ID.
	CommitId string `pulumi:"commitId"`
	// Unique repository identifier.
	RepositoryId string `pulumi:"repositoryId"`
}

// A collection of values returned by getRepositoryCommit.
type GetRepositoryCommitResult struct {
	// Email of the author of the repository.
	AuthorEmail string `pulumi:"authorEmail"`
	// Name of the author of the repository.
	AuthorName string `pulumi:"authorName"`
	// Commit hash pointed to by reference name.
	CommitId string `pulumi:"commitId"`
	// The commit message.
	CommitMessage string `pulumi:"commitMessage"`
	// Email of who creates the commit.
	CommitterEmail string `pulumi:"committerEmail"`
	// Name of who creates the commit.
	CommitterName string `pulumi:"committerName"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// An array of parent commit IDs of created commit.
	ParentCommitIds []string `pulumi:"parentCommitIds"`
	RepositoryId    string   `pulumi:"repositoryId"`
	// The time at which commit was created.
	TimeCreated string `pulumi:"timeCreated"`
	// Tree information for the specified commit.
	TreeId string `pulumi:"treeId"`
}

func GetRepositoryCommitOutput(ctx *pulumi.Context, args GetRepositoryCommitOutputArgs, opts ...pulumi.InvokeOption) GetRepositoryCommitResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetRepositoryCommitResultOutput, error) {
			args := v.(GetRepositoryCommitArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DevOps/getRepositoryCommit:getRepositoryCommit", args, GetRepositoryCommitResultOutput{}, options).(GetRepositoryCommitResultOutput), nil
		}).(GetRepositoryCommitResultOutput)
}

// A collection of arguments for invoking getRepositoryCommit.
type GetRepositoryCommitOutputArgs struct {
	// A filter to return only resources that match the given commit ID.
	CommitId pulumi.StringInput `pulumi:"commitId"`
	// Unique repository identifier.
	RepositoryId pulumi.StringInput `pulumi:"repositoryId"`
}

func (GetRepositoryCommitOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRepositoryCommitArgs)(nil)).Elem()
}

// A collection of values returned by getRepositoryCommit.
type GetRepositoryCommitResultOutput struct{ *pulumi.OutputState }

func (GetRepositoryCommitResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRepositoryCommitResult)(nil)).Elem()
}

func (o GetRepositoryCommitResultOutput) ToGetRepositoryCommitResultOutput() GetRepositoryCommitResultOutput {
	return o
}

func (o GetRepositoryCommitResultOutput) ToGetRepositoryCommitResultOutputWithContext(ctx context.Context) GetRepositoryCommitResultOutput {
	return o
}

// Email of the author of the repository.
func (o GetRepositoryCommitResultOutput) AuthorEmail() pulumi.StringOutput {
	return o.ApplyT(func(v GetRepositoryCommitResult) string { return v.AuthorEmail }).(pulumi.StringOutput)
}

// Name of the author of the repository.
func (o GetRepositoryCommitResultOutput) AuthorName() pulumi.StringOutput {
	return o.ApplyT(func(v GetRepositoryCommitResult) string { return v.AuthorName }).(pulumi.StringOutput)
}

// Commit hash pointed to by reference name.
func (o GetRepositoryCommitResultOutput) CommitId() pulumi.StringOutput {
	return o.ApplyT(func(v GetRepositoryCommitResult) string { return v.CommitId }).(pulumi.StringOutput)
}

// The commit message.
func (o GetRepositoryCommitResultOutput) CommitMessage() pulumi.StringOutput {
	return o.ApplyT(func(v GetRepositoryCommitResult) string { return v.CommitMessage }).(pulumi.StringOutput)
}

// Email of who creates the commit.
func (o GetRepositoryCommitResultOutput) CommitterEmail() pulumi.StringOutput {
	return o.ApplyT(func(v GetRepositoryCommitResult) string { return v.CommitterEmail }).(pulumi.StringOutput)
}

// Name of who creates the commit.
func (o GetRepositoryCommitResultOutput) CommitterName() pulumi.StringOutput {
	return o.ApplyT(func(v GetRepositoryCommitResult) string { return v.CommitterName }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetRepositoryCommitResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetRepositoryCommitResult) string { return v.Id }).(pulumi.StringOutput)
}

// An array of parent commit IDs of created commit.
func (o GetRepositoryCommitResultOutput) ParentCommitIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetRepositoryCommitResult) []string { return v.ParentCommitIds }).(pulumi.StringArrayOutput)
}

func (o GetRepositoryCommitResultOutput) RepositoryId() pulumi.StringOutput {
	return o.ApplyT(func(v GetRepositoryCommitResult) string { return v.RepositoryId }).(pulumi.StringOutput)
}

// The time at which commit was created.
func (o GetRepositoryCommitResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v GetRepositoryCommitResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// Tree information for the specified commit.
func (o GetRepositoryCommitResultOutput) TreeId() pulumi.StringOutput {
	return o.ApplyT(func(v GetRepositoryCommitResult) string { return v.TreeId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetRepositoryCommitResultOutput{})
}
