// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Autonomous Database Software Image resource in Oracle Cloud Infrastructure Database service.
//
// Gets information about the specified Autonomous Database Software Image.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/database"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := database.GetAutonomousDatabaseSoftwareImage(ctx, &database.GetAutonomousDatabaseSoftwareImageArgs{
//				AutonomousDatabaseSoftwareImageId: testAutonomousDatabaseSoftwareImageOciDatabaseAutonomousDatabaseSoftwareImage.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupAutonomousDatabaseSoftwareImage(ctx *pulumi.Context, args *LookupAutonomousDatabaseSoftwareImageArgs, opts ...pulumi.InvokeOption) (*LookupAutonomousDatabaseSoftwareImageResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupAutonomousDatabaseSoftwareImageResult
	err := ctx.Invoke("oci:Database/getAutonomousDatabaseSoftwareImage:getAutonomousDatabaseSoftwareImage", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAutonomousDatabaseSoftwareImage.
type LookupAutonomousDatabaseSoftwareImageArgs struct {
	// The Autonomous Database Software Image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousDatabaseSoftwareImageId string `pulumi:"autonomousDatabaseSoftwareImageId"`
}

// A collection of values returned by getAutonomousDatabaseSoftwareImage.
type LookupAutonomousDatabaseSoftwareImageResult struct {
	AutonomousDatabaseSoftwareImageId string `pulumi:"autonomousDatabaseSoftwareImageId"`
	// One-off patches included in the Autonomous Database Software Image
	AutonomousDsiOneOffPatches []string `pulumi:"autonomousDsiOneOffPatches"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The database version with which the Autonomous Database Software Image is to be built.
	DatabaseVersion string `pulumi:"databaseVersion"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The user-friendly name for the Autonomous Database Software Image. The name does not have to be unique.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database Software Image.
	Id string `pulumi:"id"`
	// To what shape the image is meant for.
	ImageShapeFamily string `pulumi:"imageShapeFamily"`
	// Detailed message for the lifecycle state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The Release Updates.
	ReleaseUpdate string `pulumi:"releaseUpdate"`
	SourceCdbId   string `pulumi:"sourceCdbId"`
	// The current state of the Autonomous Database Software Image.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time the Autonomous Database Software Image was created.
	TimeCreated string `pulumi:"timeCreated"`
}

func LookupAutonomousDatabaseSoftwareImageOutput(ctx *pulumi.Context, args LookupAutonomousDatabaseSoftwareImageOutputArgs, opts ...pulumi.InvokeOption) LookupAutonomousDatabaseSoftwareImageResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupAutonomousDatabaseSoftwareImageResultOutput, error) {
			args := v.(LookupAutonomousDatabaseSoftwareImageArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Database/getAutonomousDatabaseSoftwareImage:getAutonomousDatabaseSoftwareImage", args, LookupAutonomousDatabaseSoftwareImageResultOutput{}, options).(LookupAutonomousDatabaseSoftwareImageResultOutput), nil
		}).(LookupAutonomousDatabaseSoftwareImageResultOutput)
}

// A collection of arguments for invoking getAutonomousDatabaseSoftwareImage.
type LookupAutonomousDatabaseSoftwareImageOutputArgs struct {
	// The Autonomous Database Software Image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousDatabaseSoftwareImageId pulumi.StringInput `pulumi:"autonomousDatabaseSoftwareImageId"`
}

func (LookupAutonomousDatabaseSoftwareImageOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupAutonomousDatabaseSoftwareImageArgs)(nil)).Elem()
}

// A collection of values returned by getAutonomousDatabaseSoftwareImage.
type LookupAutonomousDatabaseSoftwareImageResultOutput struct{ *pulumi.OutputState }

func (LookupAutonomousDatabaseSoftwareImageResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupAutonomousDatabaseSoftwareImageResult)(nil)).Elem()
}

func (o LookupAutonomousDatabaseSoftwareImageResultOutput) ToLookupAutonomousDatabaseSoftwareImageResultOutput() LookupAutonomousDatabaseSoftwareImageResultOutput {
	return o
}

func (o LookupAutonomousDatabaseSoftwareImageResultOutput) ToLookupAutonomousDatabaseSoftwareImageResultOutputWithContext(ctx context.Context) LookupAutonomousDatabaseSoftwareImageResultOutput {
	return o
}

func (o LookupAutonomousDatabaseSoftwareImageResultOutput) AutonomousDatabaseSoftwareImageId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousDatabaseSoftwareImageResult) string { return v.AutonomousDatabaseSoftwareImageId }).(pulumi.StringOutput)
}

// One-off patches included in the Autonomous Database Software Image
func (o LookupAutonomousDatabaseSoftwareImageResultOutput) AutonomousDsiOneOffPatches() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupAutonomousDatabaseSoftwareImageResult) []string { return v.AutonomousDsiOneOffPatches }).(pulumi.StringArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o LookupAutonomousDatabaseSoftwareImageResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousDatabaseSoftwareImageResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The database version with which the Autonomous Database Software Image is to be built.
func (o LookupAutonomousDatabaseSoftwareImageResultOutput) DatabaseVersion() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousDatabaseSoftwareImageResult) string { return v.DatabaseVersion }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
func (o LookupAutonomousDatabaseSoftwareImageResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupAutonomousDatabaseSoftwareImageResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The user-friendly name for the Autonomous Database Software Image. The name does not have to be unique.
func (o LookupAutonomousDatabaseSoftwareImageResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousDatabaseSoftwareImageResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o LookupAutonomousDatabaseSoftwareImageResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupAutonomousDatabaseSoftwareImageResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database Software Image.
func (o LookupAutonomousDatabaseSoftwareImageResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousDatabaseSoftwareImageResult) string { return v.Id }).(pulumi.StringOutput)
}

// To what shape the image is meant for.
func (o LookupAutonomousDatabaseSoftwareImageResultOutput) ImageShapeFamily() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousDatabaseSoftwareImageResult) string { return v.ImageShapeFamily }).(pulumi.StringOutput)
}

// Detailed message for the lifecycle state.
func (o LookupAutonomousDatabaseSoftwareImageResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousDatabaseSoftwareImageResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The Release Updates.
func (o LookupAutonomousDatabaseSoftwareImageResultOutput) ReleaseUpdate() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousDatabaseSoftwareImageResult) string { return v.ReleaseUpdate }).(pulumi.StringOutput)
}

func (o LookupAutonomousDatabaseSoftwareImageResultOutput) SourceCdbId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousDatabaseSoftwareImageResult) string { return v.SourceCdbId }).(pulumi.StringOutput)
}

// The current state of the Autonomous Database Software Image.
func (o LookupAutonomousDatabaseSoftwareImageResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousDatabaseSoftwareImageResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
func (o LookupAutonomousDatabaseSoftwareImageResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupAutonomousDatabaseSoftwareImageResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time the Autonomous Database Software Image was created.
func (o LookupAutonomousDatabaseSoftwareImageResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousDatabaseSoftwareImageResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupAutonomousDatabaseSoftwareImageResultOutput{})
}
