// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package capacitymanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Occ Availability Catalog resource in Oracle Cloud Infrastructure Capacity Management service.
//
// Get details about availability catalog.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/capacitymanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := capacitymanagement.GetOccAvailabilityCatalog(ctx, &capacitymanagement.GetOccAvailabilityCatalogArgs{
//				OccAvailabilityCatalogId: testOccAvailabilityCatalogOciCapacityManagementOccAvailabilityCatalog.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupOccAvailabilityCatalog(ctx *pulumi.Context, args *LookupOccAvailabilityCatalogArgs, opts ...pulumi.InvokeOption) (*LookupOccAvailabilityCatalogResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupOccAvailabilityCatalogResult
	err := ctx.Invoke("oci:CapacityManagement/getOccAvailabilityCatalog:getOccAvailabilityCatalog", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getOccAvailabilityCatalog.
type LookupOccAvailabilityCatalogArgs struct {
	// The OCID of the availability catalog.
	OccAvailabilityCatalogId string `pulumi:"occAvailabilityCatalogId"`
}

// A collection of values returned by getOccAvailabilityCatalog.
type LookupOccAvailabilityCatalogResult struct {
	Base64encodedCatalogDetails string `pulumi:"base64encodedCatalogDetails"`
	// The different states associated with the availability catalog.
	CatalogState string `pulumi:"catalogState"`
	// The OCID of the tenancy where the availability catalog resides.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Text information about the availability catalog.
	Description string `pulumi:"description"`
	// Details about capacity available for different resources in catalog.
	Details []GetOccAvailabilityCatalogDetail `pulumi:"details"`
	// A user-friendly name for the availability catalog.
	DisplayName string `pulumi:"displayName"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of the availability catalog.
	Id string `pulumi:"id"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed State.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// Used for representing the metadata of the catalog. This denotes the version and format of the CSV file for parsing.
	MetadataDetails []GetOccAvailabilityCatalogMetadataDetail `pulumi:"metadataDetails"`
	// The name of the Oracle Cloud Infrastructure service in consideration. For example, Compute, Exadata, and so on.
	Namespace                string `pulumi:"namespace"`
	OccAvailabilityCatalogId string `pulumi:"occAvailabilityCatalogId"`
	// The customer group OCID to which the availability catalog belongs.
	OccCustomerGroupId string `pulumi:"occCustomerGroupId"`
	// The current lifecycle state of the resource.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time when the availability catalog was created.
	TimeCreated string `pulumi:"timeCreated"`
	// The time when the availability catalog was last updated.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupOccAvailabilityCatalogOutput(ctx *pulumi.Context, args LookupOccAvailabilityCatalogOutputArgs, opts ...pulumi.InvokeOption) LookupOccAvailabilityCatalogResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupOccAvailabilityCatalogResultOutput, error) {
			args := v.(LookupOccAvailabilityCatalogArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:CapacityManagement/getOccAvailabilityCatalog:getOccAvailabilityCatalog", args, LookupOccAvailabilityCatalogResultOutput{}, options).(LookupOccAvailabilityCatalogResultOutput), nil
		}).(LookupOccAvailabilityCatalogResultOutput)
}

// A collection of arguments for invoking getOccAvailabilityCatalog.
type LookupOccAvailabilityCatalogOutputArgs struct {
	// The OCID of the availability catalog.
	OccAvailabilityCatalogId pulumi.StringInput `pulumi:"occAvailabilityCatalogId"`
}

func (LookupOccAvailabilityCatalogOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupOccAvailabilityCatalogArgs)(nil)).Elem()
}

// A collection of values returned by getOccAvailabilityCatalog.
type LookupOccAvailabilityCatalogResultOutput struct{ *pulumi.OutputState }

func (LookupOccAvailabilityCatalogResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupOccAvailabilityCatalogResult)(nil)).Elem()
}

func (o LookupOccAvailabilityCatalogResultOutput) ToLookupOccAvailabilityCatalogResultOutput() LookupOccAvailabilityCatalogResultOutput {
	return o
}

func (o LookupOccAvailabilityCatalogResultOutput) ToLookupOccAvailabilityCatalogResultOutputWithContext(ctx context.Context) LookupOccAvailabilityCatalogResultOutput {
	return o
}

func (o LookupOccAvailabilityCatalogResultOutput) Base64encodedCatalogDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOccAvailabilityCatalogResult) string { return v.Base64encodedCatalogDetails }).(pulumi.StringOutput)
}

// The different states associated with the availability catalog.
func (o LookupOccAvailabilityCatalogResultOutput) CatalogState() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOccAvailabilityCatalogResult) string { return v.CatalogState }).(pulumi.StringOutput)
}

// The OCID of the tenancy where the availability catalog resides.
func (o LookupOccAvailabilityCatalogResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOccAvailabilityCatalogResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupOccAvailabilityCatalogResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupOccAvailabilityCatalogResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Text information about the availability catalog.
func (o LookupOccAvailabilityCatalogResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOccAvailabilityCatalogResult) string { return v.Description }).(pulumi.StringOutput)
}

// Details about capacity available for different resources in catalog.
func (o LookupOccAvailabilityCatalogResultOutput) Details() GetOccAvailabilityCatalogDetailArrayOutput {
	return o.ApplyT(func(v LookupOccAvailabilityCatalogResult) []GetOccAvailabilityCatalogDetail { return v.Details }).(GetOccAvailabilityCatalogDetailArrayOutput)
}

// A user-friendly name for the availability catalog.
func (o LookupOccAvailabilityCatalogResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOccAvailabilityCatalogResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupOccAvailabilityCatalogResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupOccAvailabilityCatalogResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The OCID of the availability catalog.
func (o LookupOccAvailabilityCatalogResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOccAvailabilityCatalogResult) string { return v.Id }).(pulumi.StringOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed State.
func (o LookupOccAvailabilityCatalogResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOccAvailabilityCatalogResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Used for representing the metadata of the catalog. This denotes the version and format of the CSV file for parsing.
func (o LookupOccAvailabilityCatalogResultOutput) MetadataDetails() GetOccAvailabilityCatalogMetadataDetailArrayOutput {
	return o.ApplyT(func(v LookupOccAvailabilityCatalogResult) []GetOccAvailabilityCatalogMetadataDetail {
		return v.MetadataDetails
	}).(GetOccAvailabilityCatalogMetadataDetailArrayOutput)
}

// The name of the Oracle Cloud Infrastructure service in consideration. For example, Compute, Exadata, and so on.
func (o LookupOccAvailabilityCatalogResultOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOccAvailabilityCatalogResult) string { return v.Namespace }).(pulumi.StringOutput)
}

func (o LookupOccAvailabilityCatalogResultOutput) OccAvailabilityCatalogId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOccAvailabilityCatalogResult) string { return v.OccAvailabilityCatalogId }).(pulumi.StringOutput)
}

// The customer group OCID to which the availability catalog belongs.
func (o LookupOccAvailabilityCatalogResultOutput) OccCustomerGroupId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOccAvailabilityCatalogResult) string { return v.OccCustomerGroupId }).(pulumi.StringOutput)
}

// The current lifecycle state of the resource.
func (o LookupOccAvailabilityCatalogResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOccAvailabilityCatalogResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupOccAvailabilityCatalogResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupOccAvailabilityCatalogResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time when the availability catalog was created.
func (o LookupOccAvailabilityCatalogResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOccAvailabilityCatalogResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time when the availability catalog was last updated.
func (o LookupOccAvailabilityCatalogResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOccAvailabilityCatalogResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupOccAvailabilityCatalogResultOutput{})
}
