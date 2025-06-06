// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package stackmonitoring

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Discovery Job resource in Oracle Cloud Infrastructure Stack Monitoring service.
//
// API to create discovery Job and submit discovery Details to agent.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/stackmonitoring"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := stackmonitoring.NewDiscoveryJob(ctx, "test_discovery_job", &stackmonitoring.DiscoveryJobArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				DiscoveryDetails: &stackmonitoring.DiscoveryJobDiscoveryDetailsArgs{
//					AgentId: pulumi.Any(managementAgentId),
//					Properties: &stackmonitoring.DiscoveryJobDiscoveryDetailsPropertiesArgs{
//						PropertiesMap: pulumi.Any(discoveryJobDiscoveryDetailsPropertiesPropertiesMap),
//					},
//					ResourceName: pulumi.Any(discoveryJobDiscoveryDetailsResourceName),
//					ResourceType: pulumi.Any(discoveryJobDiscoveryDetailsResourceType),
//					Credentials: &stackmonitoring.DiscoveryJobDiscoveryDetailsCredentialsArgs{
//						Items: stackmonitoring.DiscoveryJobDiscoveryDetailsCredentialsItemArray{
//							&stackmonitoring.DiscoveryJobDiscoveryDetailsCredentialsItemArgs{
//								CredentialName: pulumi.Any(discoveryJobDiscoveryDetailsCredentialsItemsCredentialName),
//								CredentialType: pulumi.Any(discoveryJobDiscoveryDetailsCredentialsItemsCredentialType),
//								Properties: &stackmonitoring.DiscoveryJobDiscoveryDetailsCredentialsItemPropertiesArgs{
//									PropertiesMap: pulumi.Any(discoveryJobDiscoveryDetailsCredentialsItemsPropertiesPropertiesMap),
//								},
//							},
//						},
//					},
//					License: pulumi.Any(discoveryJobDiscoveryDetailsLicense),
//					Tags: &stackmonitoring.DiscoveryJobDiscoveryDetailsTagsArgs{
//						PropertiesMap: pulumi.Any(discoveryJobDiscoveryDetailsTagsPropertiesMap),
//					},
//				},
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				DiscoveryClient: pulumi.Any(discoveryJobDiscoveryClient),
//				DiscoveryType:   pulumi.Any(discoveryJobDiscoveryType),
//				FreeformTags: pulumi.StringMap{
//					"bar-key": pulumi.String("value"),
//				},
//				ShouldPropagateTagsToDiscoveredResources: pulumi.Any(discoveryJobShouldPropagateTagsToDiscoveredResources),
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// DiscoveryJobs can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:StackMonitoring/discoveryJob:DiscoveryJob test_discovery_job "id"
// ```
type DiscoveryJob struct {
	pulumi.CustomResourceState

	// The OCID of Compartment
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// Client who submits discovery job.
	DiscoveryClient pulumi.StringOutput `pulumi:"discoveryClient"`
	// The request of DiscoveryJob Resource details.
	DiscoveryDetails DiscoveryJobDiscoveryDetailsOutput `pulumi:"discoveryDetails"`
	// Add option submits new discovery Job. Add with retry option to re-submit failed discovery job. Refresh option refreshes the existing discovered resources.
	DiscoveryType pulumi.StringPtrOutput `pulumi:"discoveryType"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// If this parameter set to true, the specified tags will be applied  to all resources discovered in the current request.  Default is true.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ShouldPropagateTagsToDiscoveredResources pulumi.BoolOutput `pulumi:"shouldPropagateTagsToDiscoveredResources"`
	// The current state of the DiscoveryJob Resource.
	State pulumi.StringOutput `pulumi:"state"`
	// Specifies the status of the discovery job
	Status pulumi.StringOutput `pulumi:"status"`
	// The short summary of the status of the discovery job
	StatusMessage pulumi.StringOutput `pulumi:"statusMessage"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The OCID of Tenant
	TenantId pulumi.StringOutput `pulumi:"tenantId"`
	// The time the discovery Job was updated.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// The OCID of user in which the job is submitted
	UserId pulumi.StringOutput `pulumi:"userId"`
}

// NewDiscoveryJob registers a new resource with the given unique name, arguments, and options.
func NewDiscoveryJob(ctx *pulumi.Context,
	name string, args *DiscoveryJobArgs, opts ...pulumi.ResourceOption) (*DiscoveryJob, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DiscoveryDetails == nil {
		return nil, errors.New("invalid value for required argument 'DiscoveryDetails'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource DiscoveryJob
	err := ctx.RegisterResource("oci:StackMonitoring/discoveryJob:DiscoveryJob", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDiscoveryJob gets an existing DiscoveryJob resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDiscoveryJob(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DiscoveryJobState, opts ...pulumi.ResourceOption) (*DiscoveryJob, error) {
	var resource DiscoveryJob
	err := ctx.ReadResource("oci:StackMonitoring/discoveryJob:DiscoveryJob", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DiscoveryJob resources.
type discoveryJobState struct {
	// The OCID of Compartment
	CompartmentId *string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Client who submits discovery job.
	DiscoveryClient *string `pulumi:"discoveryClient"`
	// The request of DiscoveryJob Resource details.
	DiscoveryDetails *DiscoveryJobDiscoveryDetails `pulumi:"discoveryDetails"`
	// Add option submits new discovery Job. Add with retry option to re-submit failed discovery job. Refresh option refreshes the existing discovered resources.
	DiscoveryType *string `pulumi:"discoveryType"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// If this parameter set to true, the specified tags will be applied  to all resources discovered in the current request.  Default is true.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ShouldPropagateTagsToDiscoveredResources *bool `pulumi:"shouldPropagateTagsToDiscoveredResources"`
	// The current state of the DiscoveryJob Resource.
	State *string `pulumi:"state"`
	// Specifies the status of the discovery job
	Status *string `pulumi:"status"`
	// The short summary of the status of the discovery job
	StatusMessage *string `pulumi:"statusMessage"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The OCID of Tenant
	TenantId *string `pulumi:"tenantId"`
	// The time the discovery Job was updated.
	TimeUpdated *string `pulumi:"timeUpdated"`
	// The OCID of user in which the job is submitted
	UserId *string `pulumi:"userId"`
}

type DiscoveryJobState struct {
	// The OCID of Compartment
	CompartmentId pulumi.StringPtrInput
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// Client who submits discovery job.
	DiscoveryClient pulumi.StringPtrInput
	// The request of DiscoveryJob Resource details.
	DiscoveryDetails DiscoveryJobDiscoveryDetailsPtrInput
	// Add option submits new discovery Job. Add with retry option to re-submit failed discovery job. Refresh option refreshes the existing discovered resources.
	DiscoveryType pulumi.StringPtrInput
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// If this parameter set to true, the specified tags will be applied  to all resources discovered in the current request.  Default is true.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ShouldPropagateTagsToDiscoveredResources pulumi.BoolPtrInput
	// The current state of the DiscoveryJob Resource.
	State pulumi.StringPtrInput
	// Specifies the status of the discovery job
	Status pulumi.StringPtrInput
	// The short summary of the status of the discovery job
	StatusMessage pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The OCID of Tenant
	TenantId pulumi.StringPtrInput
	// The time the discovery Job was updated.
	TimeUpdated pulumi.StringPtrInput
	// The OCID of user in which the job is submitted
	UserId pulumi.StringPtrInput
}

func (DiscoveryJobState) ElementType() reflect.Type {
	return reflect.TypeOf((*discoveryJobState)(nil)).Elem()
}

type discoveryJobArgs struct {
	// The OCID of Compartment
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Client who submits discovery job.
	DiscoveryClient *string `pulumi:"discoveryClient"`
	// The request of DiscoveryJob Resource details.
	DiscoveryDetails DiscoveryJobDiscoveryDetails `pulumi:"discoveryDetails"`
	// Add option submits new discovery Job. Add with retry option to re-submit failed discovery job. Refresh option refreshes the existing discovered resources.
	DiscoveryType *string `pulumi:"discoveryType"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// If this parameter set to true, the specified tags will be applied  to all resources discovered in the current request.  Default is true.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ShouldPropagateTagsToDiscoveredResources *bool `pulumi:"shouldPropagateTagsToDiscoveredResources"`
}

// The set of arguments for constructing a DiscoveryJob resource.
type DiscoveryJobArgs struct {
	// The OCID of Compartment
	CompartmentId pulumi.StringInput
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// Client who submits discovery job.
	DiscoveryClient pulumi.StringPtrInput
	// The request of DiscoveryJob Resource details.
	DiscoveryDetails DiscoveryJobDiscoveryDetailsInput
	// Add option submits new discovery Job. Add with retry option to re-submit failed discovery job. Refresh option refreshes the existing discovered resources.
	DiscoveryType pulumi.StringPtrInput
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// If this parameter set to true, the specified tags will be applied  to all resources discovered in the current request.  Default is true.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ShouldPropagateTagsToDiscoveredResources pulumi.BoolPtrInput
}

func (DiscoveryJobArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*discoveryJobArgs)(nil)).Elem()
}

type DiscoveryJobInput interface {
	pulumi.Input

	ToDiscoveryJobOutput() DiscoveryJobOutput
	ToDiscoveryJobOutputWithContext(ctx context.Context) DiscoveryJobOutput
}

func (*DiscoveryJob) ElementType() reflect.Type {
	return reflect.TypeOf((**DiscoveryJob)(nil)).Elem()
}

func (i *DiscoveryJob) ToDiscoveryJobOutput() DiscoveryJobOutput {
	return i.ToDiscoveryJobOutputWithContext(context.Background())
}

func (i *DiscoveryJob) ToDiscoveryJobOutputWithContext(ctx context.Context) DiscoveryJobOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DiscoveryJobOutput)
}

// DiscoveryJobArrayInput is an input type that accepts DiscoveryJobArray and DiscoveryJobArrayOutput values.
// You can construct a concrete instance of `DiscoveryJobArrayInput` via:
//
//	DiscoveryJobArray{ DiscoveryJobArgs{...} }
type DiscoveryJobArrayInput interface {
	pulumi.Input

	ToDiscoveryJobArrayOutput() DiscoveryJobArrayOutput
	ToDiscoveryJobArrayOutputWithContext(context.Context) DiscoveryJobArrayOutput
}

type DiscoveryJobArray []DiscoveryJobInput

func (DiscoveryJobArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DiscoveryJob)(nil)).Elem()
}

func (i DiscoveryJobArray) ToDiscoveryJobArrayOutput() DiscoveryJobArrayOutput {
	return i.ToDiscoveryJobArrayOutputWithContext(context.Background())
}

func (i DiscoveryJobArray) ToDiscoveryJobArrayOutputWithContext(ctx context.Context) DiscoveryJobArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DiscoveryJobArrayOutput)
}

// DiscoveryJobMapInput is an input type that accepts DiscoveryJobMap and DiscoveryJobMapOutput values.
// You can construct a concrete instance of `DiscoveryJobMapInput` via:
//
//	DiscoveryJobMap{ "key": DiscoveryJobArgs{...} }
type DiscoveryJobMapInput interface {
	pulumi.Input

	ToDiscoveryJobMapOutput() DiscoveryJobMapOutput
	ToDiscoveryJobMapOutputWithContext(context.Context) DiscoveryJobMapOutput
}

type DiscoveryJobMap map[string]DiscoveryJobInput

func (DiscoveryJobMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DiscoveryJob)(nil)).Elem()
}

func (i DiscoveryJobMap) ToDiscoveryJobMapOutput() DiscoveryJobMapOutput {
	return i.ToDiscoveryJobMapOutputWithContext(context.Background())
}

func (i DiscoveryJobMap) ToDiscoveryJobMapOutputWithContext(ctx context.Context) DiscoveryJobMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DiscoveryJobMapOutput)
}

type DiscoveryJobOutput struct{ *pulumi.OutputState }

func (DiscoveryJobOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DiscoveryJob)(nil)).Elem()
}

func (o DiscoveryJobOutput) ToDiscoveryJobOutput() DiscoveryJobOutput {
	return o
}

func (o DiscoveryJobOutput) ToDiscoveryJobOutputWithContext(ctx context.Context) DiscoveryJobOutput {
	return o
}

// The OCID of Compartment
func (o DiscoveryJobOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *DiscoveryJob) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o DiscoveryJobOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *DiscoveryJob) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Client who submits discovery job.
func (o DiscoveryJobOutput) DiscoveryClient() pulumi.StringOutput {
	return o.ApplyT(func(v *DiscoveryJob) pulumi.StringOutput { return v.DiscoveryClient }).(pulumi.StringOutput)
}

// The request of DiscoveryJob Resource details.
func (o DiscoveryJobOutput) DiscoveryDetails() DiscoveryJobDiscoveryDetailsOutput {
	return o.ApplyT(func(v *DiscoveryJob) DiscoveryJobDiscoveryDetailsOutput { return v.DiscoveryDetails }).(DiscoveryJobDiscoveryDetailsOutput)
}

// Add option submits new discovery Job. Add with retry option to re-submit failed discovery job. Refresh option refreshes the existing discovered resources.
func (o DiscoveryJobOutput) DiscoveryType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *DiscoveryJob) pulumi.StringPtrOutput { return v.DiscoveryType }).(pulumi.StringPtrOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o DiscoveryJobOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *DiscoveryJob) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// If this parameter set to true, the specified tags will be applied  to all resources discovered in the current request.  Default is true.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o DiscoveryJobOutput) ShouldPropagateTagsToDiscoveredResources() pulumi.BoolOutput {
	return o.ApplyT(func(v *DiscoveryJob) pulumi.BoolOutput { return v.ShouldPropagateTagsToDiscoveredResources }).(pulumi.BoolOutput)
}

// The current state of the DiscoveryJob Resource.
func (o DiscoveryJobOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *DiscoveryJob) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Specifies the status of the discovery job
func (o DiscoveryJobOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v *DiscoveryJob) pulumi.StringOutput { return v.Status }).(pulumi.StringOutput)
}

// The short summary of the status of the discovery job
func (o DiscoveryJobOutput) StatusMessage() pulumi.StringOutput {
	return o.ApplyT(func(v *DiscoveryJob) pulumi.StringOutput { return v.StatusMessage }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o DiscoveryJobOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *DiscoveryJob) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The OCID of Tenant
func (o DiscoveryJobOutput) TenantId() pulumi.StringOutput {
	return o.ApplyT(func(v *DiscoveryJob) pulumi.StringOutput { return v.TenantId }).(pulumi.StringOutput)
}

// The time the discovery Job was updated.
func (o DiscoveryJobOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *DiscoveryJob) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The OCID of user in which the job is submitted
func (o DiscoveryJobOutput) UserId() pulumi.StringOutput {
	return o.ApplyT(func(v *DiscoveryJob) pulumi.StringOutput { return v.UserId }).(pulumi.StringOutput)
}

type DiscoveryJobArrayOutput struct{ *pulumi.OutputState }

func (DiscoveryJobArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DiscoveryJob)(nil)).Elem()
}

func (o DiscoveryJobArrayOutput) ToDiscoveryJobArrayOutput() DiscoveryJobArrayOutput {
	return o
}

func (o DiscoveryJobArrayOutput) ToDiscoveryJobArrayOutputWithContext(ctx context.Context) DiscoveryJobArrayOutput {
	return o
}

func (o DiscoveryJobArrayOutput) Index(i pulumi.IntInput) DiscoveryJobOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *DiscoveryJob {
		return vs[0].([]*DiscoveryJob)[vs[1].(int)]
	}).(DiscoveryJobOutput)
}

type DiscoveryJobMapOutput struct{ *pulumi.OutputState }

func (DiscoveryJobMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DiscoveryJob)(nil)).Elem()
}

func (o DiscoveryJobMapOutput) ToDiscoveryJobMapOutput() DiscoveryJobMapOutput {
	return o
}

func (o DiscoveryJobMapOutput) ToDiscoveryJobMapOutputWithContext(ctx context.Context) DiscoveryJobMapOutput {
	return o
}

func (o DiscoveryJobMapOutput) MapIndex(k pulumi.StringInput) DiscoveryJobOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *DiscoveryJob {
		return vs[0].(map[string]*DiscoveryJob)[vs[1].(string)]
	}).(DiscoveryJobOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*DiscoveryJobInput)(nil)).Elem(), &DiscoveryJob{})
	pulumi.RegisterInputType(reflect.TypeOf((*DiscoveryJobArrayInput)(nil)).Elem(), DiscoveryJobArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*DiscoveryJobMapInput)(nil)).Elem(), DiscoveryJobMap{})
	pulumi.RegisterOutputType(DiscoveryJobOutput{})
	pulumi.RegisterOutputType(DiscoveryJobArrayOutput{})
	pulumi.RegisterOutputType(DiscoveryJobMapOutput{})
}
