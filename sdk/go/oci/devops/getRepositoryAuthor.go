// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package devops

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Repository Author resource in Oracle Cloud Infrastructure Devops service.
//
// Retrieve a list of all the authors.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/DevOps"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := DevOps.GetRepositoryAuthor(ctx, &devops.GetRepositoryAuthorArgs{
// 			RepositoryId: oci_devops_repository.Test_repository.Id,
// 			RefName:      pulumi.StringRef(_var.Repository_author_ref_name),
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetRepositoryAuthor(ctx *pulumi.Context, args *GetRepositoryAuthorArgs, opts ...pulumi.InvokeOption) (*GetRepositoryAuthorResult, error) {
	var rv GetRepositoryAuthorResult
	err := ctx.Invoke("oci:DevOps/getRepositoryAuthor:getRepositoryAuthor", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getRepositoryAuthor.
type GetRepositoryAuthorArgs struct {
	// A filter to return only resources that match the given reference name.
	RefName *string `pulumi:"refName"`
	// Unique repository identifier.
	RepositoryId string `pulumi:"repositoryId"`
}

// A collection of values returned by getRepositoryAuthor.
type GetRepositoryAuthorResult struct {
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// List of author objects.
	Items        []GetRepositoryAuthorItem `pulumi:"items"`
	RefName      *string                   `pulumi:"refName"`
	RepositoryId string                    `pulumi:"repositoryId"`
}

func GetRepositoryAuthorOutput(ctx *pulumi.Context, args GetRepositoryAuthorOutputArgs, opts ...pulumi.InvokeOption) GetRepositoryAuthorResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetRepositoryAuthorResult, error) {
			args := v.(GetRepositoryAuthorArgs)
			r, err := GetRepositoryAuthor(ctx, &args, opts...)
			var s GetRepositoryAuthorResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetRepositoryAuthorResultOutput)
}

// A collection of arguments for invoking getRepositoryAuthor.
type GetRepositoryAuthorOutputArgs struct {
	// A filter to return only resources that match the given reference name.
	RefName pulumi.StringPtrInput `pulumi:"refName"`
	// Unique repository identifier.
	RepositoryId pulumi.StringInput `pulumi:"repositoryId"`
}

func (GetRepositoryAuthorOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRepositoryAuthorArgs)(nil)).Elem()
}

// A collection of values returned by getRepositoryAuthor.
type GetRepositoryAuthorResultOutput struct{ *pulumi.OutputState }

func (GetRepositoryAuthorResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRepositoryAuthorResult)(nil)).Elem()
}

func (o GetRepositoryAuthorResultOutput) ToGetRepositoryAuthorResultOutput() GetRepositoryAuthorResultOutput {
	return o
}

func (o GetRepositoryAuthorResultOutput) ToGetRepositoryAuthorResultOutputWithContext(ctx context.Context) GetRepositoryAuthorResultOutput {
	return o
}

// The provider-assigned unique ID for this managed resource.
func (o GetRepositoryAuthorResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetRepositoryAuthorResult) string { return v.Id }).(pulumi.StringOutput)
}

// List of author objects.
func (o GetRepositoryAuthorResultOutput) Items() GetRepositoryAuthorItemArrayOutput {
	return o.ApplyT(func(v GetRepositoryAuthorResult) []GetRepositoryAuthorItem { return v.Items }).(GetRepositoryAuthorItemArrayOutput)
}

func (o GetRepositoryAuthorResultOutput) RefName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRepositoryAuthorResult) *string { return v.RefName }).(pulumi.StringPtrOutput)
}

func (o GetRepositoryAuthorResultOutput) RepositoryId() pulumi.StringOutput {
	return o.ApplyT(func(v GetRepositoryAuthorResult) string { return v.RepositoryId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetRepositoryAuthorResultOutput{})
}
