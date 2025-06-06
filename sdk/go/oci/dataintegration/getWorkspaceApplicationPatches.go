// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package dataintegration

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Workspace Application Patches in Oracle Cloud Infrastructure Data Integration service.
//
// Retrieves a list of patches in an application and provides options to filter the list. For listing changes based on a period and logical objects changed, see ListPatchChanges API.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/dataintegration"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := dataintegration.GetWorkspaceApplicationPatches(ctx, &dataintegration.GetWorkspaceApplicationPatchesArgs{
//				ApplicationKey: workspaceApplicationPatchApplicationKey,
//				WorkspaceId:    testWorkspace.Id,
//				Fields:         workspaceApplicationPatchFields,
//				Identifiers:    workspaceApplicationPatchIdentifier,
//				Name:           pulumi.StringRef(workspaceApplicationPatchName),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetWorkspaceApplicationPatches(ctx *pulumi.Context, args *GetWorkspaceApplicationPatchesArgs, opts ...pulumi.InvokeOption) (*GetWorkspaceApplicationPatchesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetWorkspaceApplicationPatchesResult
	err := ctx.Invoke("oci:DataIntegration/getWorkspaceApplicationPatches:getWorkspaceApplicationPatches", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getWorkspaceApplicationPatches.
type GetWorkspaceApplicationPatchesArgs struct {
	// The application key.
	ApplicationKey string `pulumi:"applicationKey"`
	// Specifies the fields to get for an object.
	Fields  []string                               `pulumi:"fields"`
	Filters []GetWorkspaceApplicationPatchesFilter `pulumi:"filters"`
	// Used to filter by the identifier of the published object.
	Identifiers []string `pulumi:"identifiers"`
	// Used to filter by the name of the object.
	Name *string `pulumi:"name"`
	// The workspace ID.
	WorkspaceId string `pulumi:"workspaceId"`
}

// A collection of values returned by getWorkspaceApplicationPatches.
type GetWorkspaceApplicationPatchesResult struct {
	ApplicationKey string                                 `pulumi:"applicationKey"`
	Fields         []string                               `pulumi:"fields"`
	Filters        []GetWorkspaceApplicationPatchesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Value can only contain upper case letters, underscore and numbers. It should begin with upper case letter or underscore. The value can be modified.
	Identifiers []string `pulumi:"identifiers"`
	// Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	Name *string `pulumi:"name"`
	// The list of patch_summary_collection.
	PatchSummaryCollections []GetWorkspaceApplicationPatchesPatchSummaryCollection `pulumi:"patchSummaryCollections"`
	WorkspaceId             string                                                 `pulumi:"workspaceId"`
}

func GetWorkspaceApplicationPatchesOutput(ctx *pulumi.Context, args GetWorkspaceApplicationPatchesOutputArgs, opts ...pulumi.InvokeOption) GetWorkspaceApplicationPatchesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetWorkspaceApplicationPatchesResultOutput, error) {
			args := v.(GetWorkspaceApplicationPatchesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataIntegration/getWorkspaceApplicationPatches:getWorkspaceApplicationPatches", args, GetWorkspaceApplicationPatchesResultOutput{}, options).(GetWorkspaceApplicationPatchesResultOutput), nil
		}).(GetWorkspaceApplicationPatchesResultOutput)
}

// A collection of arguments for invoking getWorkspaceApplicationPatches.
type GetWorkspaceApplicationPatchesOutputArgs struct {
	// The application key.
	ApplicationKey pulumi.StringInput `pulumi:"applicationKey"`
	// Specifies the fields to get for an object.
	Fields  pulumi.StringArrayInput                        `pulumi:"fields"`
	Filters GetWorkspaceApplicationPatchesFilterArrayInput `pulumi:"filters"`
	// Used to filter by the identifier of the published object.
	Identifiers pulumi.StringArrayInput `pulumi:"identifiers"`
	// Used to filter by the name of the object.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// The workspace ID.
	WorkspaceId pulumi.StringInput `pulumi:"workspaceId"`
}

func (GetWorkspaceApplicationPatchesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetWorkspaceApplicationPatchesArgs)(nil)).Elem()
}

// A collection of values returned by getWorkspaceApplicationPatches.
type GetWorkspaceApplicationPatchesResultOutput struct{ *pulumi.OutputState }

func (GetWorkspaceApplicationPatchesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetWorkspaceApplicationPatchesResult)(nil)).Elem()
}

func (o GetWorkspaceApplicationPatchesResultOutput) ToGetWorkspaceApplicationPatchesResultOutput() GetWorkspaceApplicationPatchesResultOutput {
	return o
}

func (o GetWorkspaceApplicationPatchesResultOutput) ToGetWorkspaceApplicationPatchesResultOutputWithContext(ctx context.Context) GetWorkspaceApplicationPatchesResultOutput {
	return o
}

func (o GetWorkspaceApplicationPatchesResultOutput) ApplicationKey() pulumi.StringOutput {
	return o.ApplyT(func(v GetWorkspaceApplicationPatchesResult) string { return v.ApplicationKey }).(pulumi.StringOutput)
}

func (o GetWorkspaceApplicationPatchesResultOutput) Fields() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetWorkspaceApplicationPatchesResult) []string { return v.Fields }).(pulumi.StringArrayOutput)
}

func (o GetWorkspaceApplicationPatchesResultOutput) Filters() GetWorkspaceApplicationPatchesFilterArrayOutput {
	return o.ApplyT(func(v GetWorkspaceApplicationPatchesResult) []GetWorkspaceApplicationPatchesFilter { return v.Filters }).(GetWorkspaceApplicationPatchesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetWorkspaceApplicationPatchesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetWorkspaceApplicationPatchesResult) string { return v.Id }).(pulumi.StringOutput)
}

// Value can only contain upper case letters, underscore and numbers. It should begin with upper case letter or underscore. The value can be modified.
func (o GetWorkspaceApplicationPatchesResultOutput) Identifiers() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetWorkspaceApplicationPatchesResult) []string { return v.Identifiers }).(pulumi.StringArrayOutput)
}

// Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
func (o GetWorkspaceApplicationPatchesResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetWorkspaceApplicationPatchesResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The list of patch_summary_collection.
func (o GetWorkspaceApplicationPatchesResultOutput) PatchSummaryCollections() GetWorkspaceApplicationPatchesPatchSummaryCollectionArrayOutput {
	return o.ApplyT(func(v GetWorkspaceApplicationPatchesResult) []GetWorkspaceApplicationPatchesPatchSummaryCollection {
		return v.PatchSummaryCollections
	}).(GetWorkspaceApplicationPatchesPatchSummaryCollectionArrayOutput)
}

func (o GetWorkspaceApplicationPatchesResultOutput) WorkspaceId() pulumi.StringOutput {
	return o.ApplyT(func(v GetWorkspaceApplicationPatchesResult) string { return v.WorkspaceId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetWorkspaceApplicationPatchesResultOutput{})
}
