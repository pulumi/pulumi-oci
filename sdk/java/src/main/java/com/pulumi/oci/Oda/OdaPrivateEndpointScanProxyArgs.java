// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Oda;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Oda.inputs.OdaPrivateEndpointScanProxyScanListenerInfoArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;


public final class OdaPrivateEndpointScanProxyArgs extends com.pulumi.resources.ResourceArgs {

    public static final OdaPrivateEndpointScanProxyArgs Empty = new OdaPrivateEndpointScanProxyArgs();

    /**
     * Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="odaPrivateEndpointId", required=true)
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
    @Import(name="protocol", required=true)
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
    @Import(name="scanListenerInfos", required=true)
    private Output<List<OdaPrivateEndpointScanProxyScanListenerInfoArgs>> scanListenerInfos;

    /**
     * @return The FQDN/IPs and port information of customer&#39;s Real Application Cluster (RAC)&#39;s SCAN listeners.
     * 
     */
    public Output<List<OdaPrivateEndpointScanProxyScanListenerInfoArgs>> scanListenerInfos() {
        return this.scanListenerInfos;
    }

    /**
     * Type indicating whether Scan listener is specified by its FQDN or list of IPs
     * 
     */
    @Import(name="scanListenerType", required=true)
    private Output<String> scanListenerType;

    /**
     * @return Type indicating whether Scan listener is specified by its FQDN or list of IPs
     * 
     */
    public Output<String> scanListenerType() {
        return this.scanListenerType;
    }

    private OdaPrivateEndpointScanProxyArgs() {}

    private OdaPrivateEndpointScanProxyArgs(OdaPrivateEndpointScanProxyArgs $) {
        this.odaPrivateEndpointId = $.odaPrivateEndpointId;
        this.protocol = $.protocol;
        this.scanListenerInfos = $.scanListenerInfos;
        this.scanListenerType = $.scanListenerType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(OdaPrivateEndpointScanProxyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private OdaPrivateEndpointScanProxyArgs $;

        public Builder() {
            $ = new OdaPrivateEndpointScanProxyArgs();
        }

        public Builder(OdaPrivateEndpointScanProxyArgs defaults) {
            $ = new OdaPrivateEndpointScanProxyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param odaPrivateEndpointId Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder odaPrivateEndpointId(Output<String> odaPrivateEndpointId) {
            $.odaPrivateEndpointId = odaPrivateEndpointId;
            return this;
        }

        /**
         * @param odaPrivateEndpointId Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder odaPrivateEndpointId(String odaPrivateEndpointId) {
            return odaPrivateEndpointId(Output.of(odaPrivateEndpointId));
        }

        /**
         * @param protocol The protocol used for communication between client, scanProxy and RAC&#39;s scan listeners
         * 
         * @return builder
         * 
         */
        public Builder protocol(Output<String> protocol) {
            $.protocol = protocol;
            return this;
        }

        /**
         * @param protocol The protocol used for communication between client, scanProxy and RAC&#39;s scan listeners
         * 
         * @return builder
         * 
         */
        public Builder protocol(String protocol) {
            return protocol(Output.of(protocol));
        }

        /**
         * @param scanListenerInfos The FQDN/IPs and port information of customer&#39;s Real Application Cluster (RAC)&#39;s SCAN listeners.
         * 
         * @return builder
         * 
         */
        public Builder scanListenerInfos(Output<List<OdaPrivateEndpointScanProxyScanListenerInfoArgs>> scanListenerInfos) {
            $.scanListenerInfos = scanListenerInfos;
            return this;
        }

        /**
         * @param scanListenerInfos The FQDN/IPs and port information of customer&#39;s Real Application Cluster (RAC)&#39;s SCAN listeners.
         * 
         * @return builder
         * 
         */
        public Builder scanListenerInfos(List<OdaPrivateEndpointScanProxyScanListenerInfoArgs> scanListenerInfos) {
            return scanListenerInfos(Output.of(scanListenerInfos));
        }

        /**
         * @param scanListenerInfos The FQDN/IPs and port information of customer&#39;s Real Application Cluster (RAC)&#39;s SCAN listeners.
         * 
         * @return builder
         * 
         */
        public Builder scanListenerInfos(OdaPrivateEndpointScanProxyScanListenerInfoArgs... scanListenerInfos) {
            return scanListenerInfos(List.of(scanListenerInfos));
        }

        /**
         * @param scanListenerType Type indicating whether Scan listener is specified by its FQDN or list of IPs
         * 
         * @return builder
         * 
         */
        public Builder scanListenerType(Output<String> scanListenerType) {
            $.scanListenerType = scanListenerType;
            return this;
        }

        /**
         * @param scanListenerType Type indicating whether Scan listener is specified by its FQDN or list of IPs
         * 
         * @return builder
         * 
         */
        public Builder scanListenerType(String scanListenerType) {
            return scanListenerType(Output.of(scanListenerType));
        }

        public OdaPrivateEndpointScanProxyArgs build() {
            $.odaPrivateEndpointId = Objects.requireNonNull($.odaPrivateEndpointId, "expected parameter 'odaPrivateEndpointId' to be non-null");
            $.protocol = Objects.requireNonNull($.protocol, "expected parameter 'protocol' to be non-null");
            $.scanListenerInfos = Objects.requireNonNull($.scanListenerInfos, "expected parameter 'scanListenerInfos' to be non-null");
            $.scanListenerType = Objects.requireNonNull($.scanListenerType, "expected parameter 'scanListenerType' to be non-null");
            return $;
        }
    }

}