// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package apmconfig

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Config resource in Oracle Cloud Infrastructure Apm Config service.
//
// Gets the configuration item identified by the OCID.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/ApmConfig"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := ApmConfig.GetConfig(ctx, &apmconfig.GetConfigArgs{
//				ApmDomainId: oci_apm_apm_domain.Test_apm_domain.Id,
//				ConfigId:    oci_apm_config_config.Test_config.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupConfig(ctx *pulumi.Context, args *LookupConfigArgs, opts ...pulumi.InvokeOption) (*LookupConfigResult, error) {
	var rv LookupConfigResult
	err := ctx.Invoke("oci:ApmConfig/getConfig:getConfig", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getConfig.
type LookupConfigArgs struct {
	// The APM Domain ID the request is intended for.
	ApmDomainId string `pulumi:"apmDomainId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the configuration item.
	ConfigId string `pulumi:"configId"`
}

// A collection of values returned by getConfig.
type LookupConfigResult struct {
	ApmDomainId string `pulumi:"apmDomainId"`
	ConfigId    string `pulumi:"configId"`
	// The type of configuration item.
	ConfigType string `pulumi:"configType"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// A description of the metric.
	Description string `pulumi:"description"`
	// A list of dimensions for the metric. This variable should not be used.
	Dimensions []GetConfigDimension `pulumi:"dimensions"`
	// The name by which a configuration entity is displayed to the end user.
	DisplayName string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Span Filter. The filterId is mandatory for the creation of MetricGroups. A filterId is generated when a Span Filter is created.
	FilterId string `pulumi:"filterId"`
	// The string that defines the Span Filter expression.
	FilterText string `pulumi:"filterText"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// A string that specifies the group that an OPTIONS item belongs to.
	Group string `pulumi:"group"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the configuration item. An OCID is generated when the item is created.
	Id string `pulumi:"id"`
	// The list of metrics in this group.
	Metrics []GetConfigMetric `pulumi:"metrics"`
	// The namespace to which the metrics are published. It must be one of several predefined namespaces.
	Namespace string `pulumi:"namespace"`
	OpcDryRun string `pulumi:"opcDryRun"`
	// The options are stored here as JSON.
	Options string          `pulumi:"options"`
	Rules   []GetConfigRule `pulumi:"rules"`
	// The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
	TimeCreated string `pulumi:"timeCreated"`
	// The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupConfigOutput(ctx *pulumi.Context, args LookupConfigOutputArgs, opts ...pulumi.InvokeOption) LookupConfigResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupConfigResult, error) {
			args := v.(LookupConfigArgs)
			r, err := LookupConfig(ctx, &args, opts...)
			var s LookupConfigResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupConfigResultOutput)
}

// A collection of arguments for invoking getConfig.
type LookupConfigOutputArgs struct {
	// The APM Domain ID the request is intended for.
	ApmDomainId pulumi.StringInput `pulumi:"apmDomainId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the configuration item.
	ConfigId pulumi.StringInput `pulumi:"configId"`
}

func (LookupConfigOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupConfigArgs)(nil)).Elem()
}

// A collection of values returned by getConfig.
type LookupConfigResultOutput struct{ *pulumi.OutputState }

func (LookupConfigResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupConfigResult)(nil)).Elem()
}

func (o LookupConfigResultOutput) ToLookupConfigResultOutput() LookupConfigResultOutput {
	return o
}

func (o LookupConfigResultOutput) ToLookupConfigResultOutputWithContext(ctx context.Context) LookupConfigResultOutput {
	return o
}

func (o LookupConfigResultOutput) ApmDomainId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConfigResult) string { return v.ApmDomainId }).(pulumi.StringOutput)
}

func (o LookupConfigResultOutput) ConfigId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConfigResult) string { return v.ConfigId }).(pulumi.StringOutput)
}

// The type of configuration item.
func (o LookupConfigResultOutput) ConfigType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConfigResult) string { return v.ConfigType }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupConfigResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupConfigResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// A description of the metric.
func (o LookupConfigResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConfigResult) string { return v.Description }).(pulumi.StringOutput)
}

// A list of dimensions for the metric. This variable should not be used.
func (o LookupConfigResultOutput) Dimensions() GetConfigDimensionArrayOutput {
	return o.ApplyT(func(v LookupConfigResult) []GetConfigDimension { return v.Dimensions }).(GetConfigDimensionArrayOutput)
}

// The name by which a configuration entity is displayed to the end user.
func (o LookupConfigResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConfigResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Span Filter. The filterId is mandatory for the creation of MetricGroups. A filterId is generated when a Span Filter is created.
func (o LookupConfigResultOutput) FilterId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConfigResult) string { return v.FilterId }).(pulumi.StringOutput)
}

// The string that defines the Span Filter expression.
func (o LookupConfigResultOutput) FilterText() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConfigResult) string { return v.FilterText }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupConfigResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupConfigResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// A string that specifies the group that an OPTIONS item belongs to.
func (o LookupConfigResultOutput) Group() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConfigResult) string { return v.Group }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the configuration item. An OCID is generated when the item is created.
func (o LookupConfigResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConfigResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of metrics in this group.
func (o LookupConfigResultOutput) Metrics() GetConfigMetricArrayOutput {
	return o.ApplyT(func(v LookupConfigResult) []GetConfigMetric { return v.Metrics }).(GetConfigMetricArrayOutput)
}

// The namespace to which the metrics are published. It must be one of several predefined namespaces.
func (o LookupConfigResultOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConfigResult) string { return v.Namespace }).(pulumi.StringOutput)
}

func (o LookupConfigResultOutput) OpcDryRun() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConfigResult) string { return v.OpcDryRun }).(pulumi.StringOutput)
}

// The options are stored here as JSON.
func (o LookupConfigResultOutput) Options() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConfigResult) string { return v.Options }).(pulumi.StringOutput)
}

func (o LookupConfigResultOutput) Rules() GetConfigRuleArrayOutput {
	return o.ApplyT(func(v LookupConfigResult) []GetConfigRule { return v.Rules }).(GetConfigRuleArrayOutput)
}

// The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
func (o LookupConfigResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConfigResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
func (o LookupConfigResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConfigResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupConfigResultOutput{})
}