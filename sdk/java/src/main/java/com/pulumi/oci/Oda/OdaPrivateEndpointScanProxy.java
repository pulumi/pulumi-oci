// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Oda;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Oda.OdaPrivateEndpointScanProxyArgs;
import com.pulumi.oci.Oda.inputs.OdaPrivateEndpointScanProxyState;
import com.pulumi.oci.Oda.outputs.OdaPrivateEndpointScanProxyScanListenerInfo;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Oda Private Endpoint Scan Proxy resource in Oracle Cloud Infrastructure Digital Assistant service.
 * 
 * Starts an asynchronous job to create an ODA Private Endpoint Scan Proxy.
 * 
 * To monitor the status of the job, take the `opc-work-request-id` response
 * header value and use it to call `GET /workRequests/{workRequestID}`.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Oda.OdaPrivateEndpointScanProxy;
 * import com.pulumi.oci.Oda.OdaPrivateEndpointScanProxyArgs;
 * import com.pulumi.oci.Oda.inputs.OdaPrivateEndpointScanProxyScanListenerInfoArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         var testOdaPrivateEndpointScanProxy = new OdaPrivateEndpointScanProxy(&#34;testOdaPrivateEndpointScanProxy&#34;, OdaPrivateEndpointScanProxyArgs.builder()        
 *             .odaPrivateEndpointId(oci_oda_oda_private_endpoint.test_oda_private_endpoint().id())
 *             .protocol(var_.oda_private_endpoint_scan_proxy_protocol())
 *             .scanListenerInfos(OdaPrivateEndpointScanProxyScanListenerInfoArgs.builder()
 *                 .scanListenerFqdn(var_.oda_private_endpoint_scan_proxy_scan_listener_infos_scan_listener_fqdn())
 *                 .scanListenerIp(var_.oda_private_endpoint_scan_proxy_scan_listener_infos_scan_listener_ip())
 *                 .scanListenerPort(var_.oda_private_endpoint_scan_proxy_scan_listener_infos_scan_listener_port())
 *                 .build())
 *             .scanListenerType(var_.oda_private_endpoint_scan_proxy_scan_listener_type())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * OdaPrivateEndpointScanProxies can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Oda/odaPrivateEndpointScanProxy:OdaPrivateEndpointScanProxy test_oda_private_endpoint_scan_proxy &#34;odaPrivateEndpoints/{odaPrivateEndpointId}/odaPrivateEndpointScanProxies/{odaPrivateEndpointScanProxyId}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Oda/odaPrivateEndpointScanProxy:OdaPrivateEndpointScanProxy")
public class OdaPrivateEndpointScanProxy extends com.pulumi.resources.CustomResource {
    /**
     * Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Export(name="odaPrivateEndpointId", type=String.class, parameters={})
    private Output<String> odaPrivateEndpointId;

    /**
     * @return Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> odaPrivateEndpointId() {
        return this.odaPrivateEndpointId;
    }
    /**
     * The protocol used for communication between client, scanProxy and RAC&#39;s scan listeners
     * 
     */
    @Export(name="protocol", type=String.class, parameters={})
    private Output<String> protocol;

    /**
     * @return The protocol used for communication between client, scanProxy and RAC&#39;s scan listeners
     * 
     */
    public Output<String> protocol() {
        return this.protocol;
    }
    /**
     * The FQDN/IPs and port information of customer&#39;s Real Application Cluster (RAC)&#39;s SCAN listeners.
     * 
     */
    @Export(name="scanListenerInfos", type=List.class, parameters={OdaPrivateEndpointScanProxyScanListenerInfo.class})
    private Output<List<OdaPrivateEndpointScanProxyScanListenerInfo>> scanListenerInfos;

    /**
     * @return The FQDN/IPs and port information of customer&#39;s Real Application Cluster (RAC)&#39;s SCAN listeners.
     * 
     */
    public Output<List<OdaPrivateEndpointScanProxyScanListenerInfo>> scanListenerInfos() {
        return this.scanListenerInfos;
    }
    /**
     * Type indicating whether Scan listener is specified by its FQDN or list of IPs
     * 
     */
    @Export(name="scanListenerType", type=String.class, parameters={})
    private Output<String> scanListenerType;

    /**
     * @return Type indicating whether Scan listener is specified by its FQDN or list of IPs
     * 
     */
    public Output<String> scanListenerType() {
        return this.scanListenerType;
    }
    /**
     * The current state of the ODA Private Endpoint Scan Proxy.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the ODA Private Endpoint Scan Proxy.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * When the resource was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return When the resource was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public OdaPrivateEndpointScanProxy(String name) {
        this(name, OdaPrivateEndpointScanProxyArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public OdaPrivateEndpointScanProxy(String name, OdaPrivateEndpointScanProxyArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public OdaPrivateEndpointScanProxy(String name, OdaPrivateEndpointScanProxyArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Oda/odaPrivateEndpointScanProxy:OdaPrivateEndpointScanProxy", name, args == null ? OdaPrivateEndpointScanProxyArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private OdaPrivateEndpointScanProxy(String name, Output<String> id, @Nullable OdaPrivateEndpointScanProxyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Oda/odaPrivateEndpointScanProxy:OdaPrivateEndpointScanProxy", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static OdaPrivateEndpointScanProxy get(String name, Output<String> id, @Nullable OdaPrivateEndpointScanProxyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new OdaPrivateEndpointScanProxy(name, id, state, options);
    }
}