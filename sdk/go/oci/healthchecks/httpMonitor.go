// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package healthchecks

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Http Monitor resource in Oracle Cloud Infrastructure Health Checks service.
//
// Creates an HTTP monitor. Vantage points will be automatically selected if not specified,
// and probes will be initiated from each vantage point to each of the targets at the frequency
// specified by `intervalInSeconds`.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/HealthChecks"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := HealthChecks.NewHttpMonitor(ctx, "testHttpMonitor", &HealthChecks.HttpMonitorArgs{
//				CompartmentId:     pulumi.Any(_var.Compartment_id),
//				DisplayName:       pulumi.Any(_var.Http_monitor_display_name),
//				IntervalInSeconds: pulumi.Any(_var.Http_monitor_interval_in_seconds),
//				Protocol:          pulumi.Any(_var.Http_monitor_protocol),
//				Targets:           pulumi.Any(_var.Http_monitor_targets),
//				DefinedTags: pulumi.AnyMap{
//					"Operations.CostCenter": pulumi.Any("42"),
//				},
//				FreeformTags: pulumi.AnyMap{
//					"Department": pulumi.Any("Finance"),
//				},
//				Headers:           pulumi.Any(_var.Http_monitor_headers),
//				IsEnabled:         pulumi.Any(_var.Http_monitor_is_enabled),
//				Method:            pulumi.Any(_var.Http_monitor_method),
//				Path:              pulumi.Any(_var.Http_monitor_path),
//				Port:              pulumi.Any(_var.Http_monitor_port),
//				TimeoutInSeconds:  pulumi.Any(_var.Http_monitor_timeout_in_seconds),
//				VantagePointNames: pulumi.Any(_var.Http_monitor_vantage_point_names),
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
// HttpMonitors can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:HealthChecks/httpMonitor:HttpMonitor test_http_monitor "id"
//
// ```
type HttpMonitor struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly and mutable name suitable for display in a user interface.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// (Updatable) A dictionary of HTTP request headers.
	Headers pulumi.MapOutput `pulumi:"headers"`
	// The region where updates must be made and where results must be fetched from.
	HomeRegion pulumi.StringOutput `pulumi:"homeRegion"`
	// (Updatable) The monitor interval in seconds. Valid values: 10, 30, and 60.
	IntervalInSeconds pulumi.IntOutput `pulumi:"intervalInSeconds"`
	// (Updatable) Enables or disables the monitor. Set to 'true' to launch monitoring.
	IsEnabled pulumi.BoolOutput `pulumi:"isEnabled"`
	// (Updatable) The supported HTTP methods available for probes.
	Method pulumi.StringOutput `pulumi:"method"`
	// (Updatable) The optional URL path to probe, including query parameters.
	Path pulumi.StringOutput `pulumi:"path"`
	// (Updatable) The port on which to probe endpoints. If unspecified, probes will use the default port of their protocol.
	Port pulumi.IntOutput `pulumi:"port"`
	// (Updatable) The supported protocols available for HTTP probes.
	Protocol pulumi.StringOutput `pulumi:"protocol"`
	// A URL for fetching the probe results.
	ResultsUrl pulumi.StringOutput `pulumi:"resultsUrl"`
	// (Updatable) A list of targets (hostnames or IP addresses) of the probe.
	Targets pulumi.StringArrayOutput `pulumi:"targets"`
	// The RFC 3339-formatted creation date and time of the probe.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// (Updatable) The probe timeout in seconds. Valid values: 10, 20, 30, and 60. The probe timeout must be less than or equal to `intervalInSeconds` for monitors.
	TimeoutInSeconds pulumi.IntOutput `pulumi:"timeoutInSeconds"`
	// (Updatable) A list of names of vantage points from which to execute the probe.
	VantagePointNames pulumi.StringArrayOutput `pulumi:"vantagePointNames"`
}

// NewHttpMonitor registers a new resource with the given unique name, arguments, and options.
func NewHttpMonitor(ctx *pulumi.Context,
	name string, args *HttpMonitorArgs, opts ...pulumi.ResourceOption) (*HttpMonitor, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.IntervalInSeconds == nil {
		return nil, errors.New("invalid value for required argument 'IntervalInSeconds'")
	}
	if args.Protocol == nil {
		return nil, errors.New("invalid value for required argument 'Protocol'")
	}
	if args.Targets == nil {
		return nil, errors.New("invalid value for required argument 'Targets'")
	}
	var resource HttpMonitor
	err := ctx.RegisterResource("oci:HealthChecks/httpMonitor:HttpMonitor", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetHttpMonitor gets an existing HttpMonitor resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetHttpMonitor(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *HttpMonitorState, opts ...pulumi.ResourceOption) (*HttpMonitor, error) {
	var resource HttpMonitor
	err := ctx.ReadResource("oci:HealthChecks/httpMonitor:HttpMonitor", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering HttpMonitor resources.
type httpMonitorState struct {
	// (Updatable) The OCID of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly and mutable name suitable for display in a user interface.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) A dictionary of HTTP request headers.
	Headers map[string]interface{} `pulumi:"headers"`
	// The region where updates must be made and where results must be fetched from.
	HomeRegion *string `pulumi:"homeRegion"`
	// (Updatable) The monitor interval in seconds. Valid values: 10, 30, and 60.
	IntervalInSeconds *int `pulumi:"intervalInSeconds"`
	// (Updatable) Enables or disables the monitor. Set to 'true' to launch monitoring.
	IsEnabled *bool `pulumi:"isEnabled"`
	// (Updatable) The supported HTTP methods available for probes.
	Method *string `pulumi:"method"`
	// (Updatable) The optional URL path to probe, including query parameters.
	Path *string `pulumi:"path"`
	// (Updatable) The port on which to probe endpoints. If unspecified, probes will use the default port of their protocol.
	Port *int `pulumi:"port"`
	// (Updatable) The supported protocols available for HTTP probes.
	Protocol *string `pulumi:"protocol"`
	// A URL for fetching the probe results.
	ResultsUrl *string `pulumi:"resultsUrl"`
	// (Updatable) A list of targets (hostnames or IP addresses) of the probe.
	Targets []string `pulumi:"targets"`
	// The RFC 3339-formatted creation date and time of the probe.
	TimeCreated *string `pulumi:"timeCreated"`
	// (Updatable) The probe timeout in seconds. Valid values: 10, 20, 30, and 60. The probe timeout must be less than or equal to `intervalInSeconds` for monitors.
	TimeoutInSeconds *int `pulumi:"timeoutInSeconds"`
	// (Updatable) A list of names of vantage points from which to execute the probe.
	VantagePointNames []string `pulumi:"vantagePointNames"`
}

type HttpMonitorState struct {
	// (Updatable) The OCID of the compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly and mutable name suitable for display in a user interface.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) A dictionary of HTTP request headers.
	Headers pulumi.MapInput
	// The region where updates must be made and where results must be fetched from.
	HomeRegion pulumi.StringPtrInput
	// (Updatable) The monitor interval in seconds. Valid values: 10, 30, and 60.
	IntervalInSeconds pulumi.IntPtrInput
	// (Updatable) Enables or disables the monitor. Set to 'true' to launch monitoring.
	IsEnabled pulumi.BoolPtrInput
	// (Updatable) The supported HTTP methods available for probes.
	Method pulumi.StringPtrInput
	// (Updatable) The optional URL path to probe, including query parameters.
	Path pulumi.StringPtrInput
	// (Updatable) The port on which to probe endpoints. If unspecified, probes will use the default port of their protocol.
	Port pulumi.IntPtrInput
	// (Updatable) The supported protocols available for HTTP probes.
	Protocol pulumi.StringPtrInput
	// A URL for fetching the probe results.
	ResultsUrl pulumi.StringPtrInput
	// (Updatable) A list of targets (hostnames or IP addresses) of the probe.
	Targets pulumi.StringArrayInput
	// The RFC 3339-formatted creation date and time of the probe.
	TimeCreated pulumi.StringPtrInput
	// (Updatable) The probe timeout in seconds. Valid values: 10, 20, 30, and 60. The probe timeout must be less than or equal to `intervalInSeconds` for monitors.
	TimeoutInSeconds pulumi.IntPtrInput
	// (Updatable) A list of names of vantage points from which to execute the probe.
	VantagePointNames pulumi.StringArrayInput
}

func (HttpMonitorState) ElementType() reflect.Type {
	return reflect.TypeOf((*httpMonitorState)(nil)).Elem()
}

type httpMonitorArgs struct {
	// (Updatable) The OCID of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly and mutable name suitable for display in a user interface.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) A dictionary of HTTP request headers.
	Headers map[string]interface{} `pulumi:"headers"`
	// (Updatable) The monitor interval in seconds. Valid values: 10, 30, and 60.
	IntervalInSeconds int `pulumi:"intervalInSeconds"`
	// (Updatable) Enables or disables the monitor. Set to 'true' to launch monitoring.
	IsEnabled *bool `pulumi:"isEnabled"`
	// (Updatable) The supported HTTP methods available for probes.
	Method *string `pulumi:"method"`
	// (Updatable) The optional URL path to probe, including query parameters.
	Path *string `pulumi:"path"`
	// (Updatable) The port on which to probe endpoints. If unspecified, probes will use the default port of their protocol.
	Port *int `pulumi:"port"`
	// (Updatable) The supported protocols available for HTTP probes.
	Protocol string `pulumi:"protocol"`
	// (Updatable) A list of targets (hostnames or IP addresses) of the probe.
	Targets []string `pulumi:"targets"`
	// (Updatable) The probe timeout in seconds. Valid values: 10, 20, 30, and 60. The probe timeout must be less than or equal to `intervalInSeconds` for monitors.
	TimeoutInSeconds *int `pulumi:"timeoutInSeconds"`
	// (Updatable) A list of names of vantage points from which to execute the probe.
	VantagePointNames []string `pulumi:"vantagePointNames"`
}

// The set of arguments for constructing a HttpMonitor resource.
type HttpMonitorArgs struct {
	// (Updatable) The OCID of the compartment.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly and mutable name suitable for display in a user interface.
	DisplayName pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) A dictionary of HTTP request headers.
	Headers pulumi.MapInput
	// (Updatable) The monitor interval in seconds. Valid values: 10, 30, and 60.
	IntervalInSeconds pulumi.IntInput
	// (Updatable) Enables or disables the monitor. Set to 'true' to launch monitoring.
	IsEnabled pulumi.BoolPtrInput
	// (Updatable) The supported HTTP methods available for probes.
	Method pulumi.StringPtrInput
	// (Updatable) The optional URL path to probe, including query parameters.
	Path pulumi.StringPtrInput
	// (Updatable) The port on which to probe endpoints. If unspecified, probes will use the default port of their protocol.
	Port pulumi.IntPtrInput
	// (Updatable) The supported protocols available for HTTP probes.
	Protocol pulumi.StringInput
	// (Updatable) A list of targets (hostnames or IP addresses) of the probe.
	Targets pulumi.StringArrayInput
	// (Updatable) The probe timeout in seconds. Valid values: 10, 20, 30, and 60. The probe timeout must be less than or equal to `intervalInSeconds` for monitors.
	TimeoutInSeconds pulumi.IntPtrInput
	// (Updatable) A list of names of vantage points from which to execute the probe.
	VantagePointNames pulumi.StringArrayInput
}

func (HttpMonitorArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*httpMonitorArgs)(nil)).Elem()
}

type HttpMonitorInput interface {
	pulumi.Input

	ToHttpMonitorOutput() HttpMonitorOutput
	ToHttpMonitorOutputWithContext(ctx context.Context) HttpMonitorOutput
}

func (*HttpMonitor) ElementType() reflect.Type {
	return reflect.TypeOf((**HttpMonitor)(nil)).Elem()
}

func (i *HttpMonitor) ToHttpMonitorOutput() HttpMonitorOutput {
	return i.ToHttpMonitorOutputWithContext(context.Background())
}

func (i *HttpMonitor) ToHttpMonitorOutputWithContext(ctx context.Context) HttpMonitorOutput {
	return pulumi.ToOutputWithContext(ctx, i).(HttpMonitorOutput)
}

// HttpMonitorArrayInput is an input type that accepts HttpMonitorArray and HttpMonitorArrayOutput values.
// You can construct a concrete instance of `HttpMonitorArrayInput` via:
//
//	HttpMonitorArray{ HttpMonitorArgs{...} }
type HttpMonitorArrayInput interface {
	pulumi.Input

	ToHttpMonitorArrayOutput() HttpMonitorArrayOutput
	ToHttpMonitorArrayOutputWithContext(context.Context) HttpMonitorArrayOutput
}

type HttpMonitorArray []HttpMonitorInput

func (HttpMonitorArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*HttpMonitor)(nil)).Elem()
}

func (i HttpMonitorArray) ToHttpMonitorArrayOutput() HttpMonitorArrayOutput {
	return i.ToHttpMonitorArrayOutputWithContext(context.Background())
}

func (i HttpMonitorArray) ToHttpMonitorArrayOutputWithContext(ctx context.Context) HttpMonitorArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(HttpMonitorArrayOutput)
}

// HttpMonitorMapInput is an input type that accepts HttpMonitorMap and HttpMonitorMapOutput values.
// You can construct a concrete instance of `HttpMonitorMapInput` via:
//
//	HttpMonitorMap{ "key": HttpMonitorArgs{...} }
type HttpMonitorMapInput interface {
	pulumi.Input

	ToHttpMonitorMapOutput() HttpMonitorMapOutput
	ToHttpMonitorMapOutputWithContext(context.Context) HttpMonitorMapOutput
}

type HttpMonitorMap map[string]HttpMonitorInput

func (HttpMonitorMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*HttpMonitor)(nil)).Elem()
}

func (i HttpMonitorMap) ToHttpMonitorMapOutput() HttpMonitorMapOutput {
	return i.ToHttpMonitorMapOutputWithContext(context.Background())
}

func (i HttpMonitorMap) ToHttpMonitorMapOutputWithContext(ctx context.Context) HttpMonitorMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(HttpMonitorMapOutput)
}

type HttpMonitorOutput struct{ *pulumi.OutputState }

func (HttpMonitorOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**HttpMonitor)(nil)).Elem()
}

func (o HttpMonitorOutput) ToHttpMonitorOutput() HttpMonitorOutput {
	return o
}

func (o HttpMonitorOutput) ToHttpMonitorOutputWithContext(ctx context.Context) HttpMonitorOutput {
	return o
}

// (Updatable) The OCID of the compartment.
func (o HttpMonitorOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *HttpMonitor) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o HttpMonitorOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *HttpMonitor) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) A user-friendly and mutable name suitable for display in a user interface.
func (o HttpMonitorOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *HttpMonitor) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o HttpMonitorOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *HttpMonitor) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// (Updatable) A dictionary of HTTP request headers.
func (o HttpMonitorOutput) Headers() pulumi.MapOutput {
	return o.ApplyT(func(v *HttpMonitor) pulumi.MapOutput { return v.Headers }).(pulumi.MapOutput)
}

// The region where updates must be made and where results must be fetched from.
func (o HttpMonitorOutput) HomeRegion() pulumi.StringOutput {
	return o.ApplyT(func(v *HttpMonitor) pulumi.StringOutput { return v.HomeRegion }).(pulumi.StringOutput)
}

// (Updatable) The monitor interval in seconds. Valid values: 10, 30, and 60.
func (o HttpMonitorOutput) IntervalInSeconds() pulumi.IntOutput {
	return o.ApplyT(func(v *HttpMonitor) pulumi.IntOutput { return v.IntervalInSeconds }).(pulumi.IntOutput)
}

// (Updatable) Enables or disables the monitor. Set to 'true' to launch monitoring.
func (o HttpMonitorOutput) IsEnabled() pulumi.BoolOutput {
	return o.ApplyT(func(v *HttpMonitor) pulumi.BoolOutput { return v.IsEnabled }).(pulumi.BoolOutput)
}

// (Updatable) The supported HTTP methods available for probes.
func (o HttpMonitorOutput) Method() pulumi.StringOutput {
	return o.ApplyT(func(v *HttpMonitor) pulumi.StringOutput { return v.Method }).(pulumi.StringOutput)
}

// (Updatable) The optional URL path to probe, including query parameters.
func (o HttpMonitorOutput) Path() pulumi.StringOutput {
	return o.ApplyT(func(v *HttpMonitor) pulumi.StringOutput { return v.Path }).(pulumi.StringOutput)
}

// (Updatable) The port on which to probe endpoints. If unspecified, probes will use the default port of their protocol.
func (o HttpMonitorOutput) Port() pulumi.IntOutput {
	return o.ApplyT(func(v *HttpMonitor) pulumi.IntOutput { return v.Port }).(pulumi.IntOutput)
}

// (Updatable) The supported protocols available for HTTP probes.
func (o HttpMonitorOutput) Protocol() pulumi.StringOutput {
	return o.ApplyT(func(v *HttpMonitor) pulumi.StringOutput { return v.Protocol }).(pulumi.StringOutput)
}

// A URL for fetching the probe results.
func (o HttpMonitorOutput) ResultsUrl() pulumi.StringOutput {
	return o.ApplyT(func(v *HttpMonitor) pulumi.StringOutput { return v.ResultsUrl }).(pulumi.StringOutput)
}

// (Updatable) A list of targets (hostnames or IP addresses) of the probe.
func (o HttpMonitorOutput) Targets() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *HttpMonitor) pulumi.StringArrayOutput { return v.Targets }).(pulumi.StringArrayOutput)
}

// The RFC 3339-formatted creation date and time of the probe.
func (o HttpMonitorOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *HttpMonitor) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// (Updatable) The probe timeout in seconds. Valid values: 10, 20, 30, and 60. The probe timeout must be less than or equal to `intervalInSeconds` for monitors.
func (o HttpMonitorOutput) TimeoutInSeconds() pulumi.IntOutput {
	return o.ApplyT(func(v *HttpMonitor) pulumi.IntOutput { return v.TimeoutInSeconds }).(pulumi.IntOutput)
}

// (Updatable) A list of names of vantage points from which to execute the probe.
func (o HttpMonitorOutput) VantagePointNames() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *HttpMonitor) pulumi.StringArrayOutput { return v.VantagePointNames }).(pulumi.StringArrayOutput)
}

type HttpMonitorArrayOutput struct{ *pulumi.OutputState }

func (HttpMonitorArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*HttpMonitor)(nil)).Elem()
}

func (o HttpMonitorArrayOutput) ToHttpMonitorArrayOutput() HttpMonitorArrayOutput {
	return o
}

func (o HttpMonitorArrayOutput) ToHttpMonitorArrayOutputWithContext(ctx context.Context) HttpMonitorArrayOutput {
	return o
}

func (o HttpMonitorArrayOutput) Index(i pulumi.IntInput) HttpMonitorOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *HttpMonitor {
		return vs[0].([]*HttpMonitor)[vs[1].(int)]
	}).(HttpMonitorOutput)
}

type HttpMonitorMapOutput struct{ *pulumi.OutputState }

func (HttpMonitorMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*HttpMonitor)(nil)).Elem()
}

func (o HttpMonitorMapOutput) ToHttpMonitorMapOutput() HttpMonitorMapOutput {
	return o
}

func (o HttpMonitorMapOutput) ToHttpMonitorMapOutputWithContext(ctx context.Context) HttpMonitorMapOutput {
	return o
}

func (o HttpMonitorMapOutput) MapIndex(k pulumi.StringInput) HttpMonitorOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *HttpMonitor {
		return vs[0].(map[string]*HttpMonitor)[vs[1].(string)]
	}).(HttpMonitorOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*HttpMonitorInput)(nil)).Elem(), &HttpMonitor{})
	pulumi.RegisterInputType(reflect.TypeOf((*HttpMonitorArrayInput)(nil)).Elem(), HttpMonitorArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*HttpMonitorMapInput)(nil)).Elem(), HttpMonitorMap{})
	pulumi.RegisterOutputType(HttpMonitorOutput{})
	pulumi.RegisterOutputType(HttpMonitorArrayOutput{})
	pulumi.RegisterOutputType(HttpMonitorMapOutput{})
}