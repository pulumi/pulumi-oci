// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Oda.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Oda.inputs.OdaPrivateEndpointScanProxyScanListenerInfoArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class OdaPrivateEndpointScanProxyState extends com.pulumi.resources.ResourceArgs {

    public static final OdaPrivateEndpointScanProxyState Empty = new OdaPrivateEndpointScanProxyState();

    /**
     * Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="odaPrivateEndpointId")
    private @Nullable Output<String> odaPrivateEndpointId;

    /**
     * @return Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Optional<Output<String>> odaPrivateEndpointId() {
        return Optional.ofNullable(this.odaPrivateEndpointId);
    }

    /**
     * The protocol used for communication between client, scanProxy and RAC&#39;s scan listeners
     * 
     */
    @Import(name="protocol")
    private @Nullable Output<String> protocol;

    /**
     * @return The protocol used for communication between client, scanProxy and RAC&#39;s scan listeners
     * 
     */
    public Optional<Output<String>> protocol() {
        return Optional.ofNullable(this.protocol);
    }

    /**
     * The FQDN/IPs and port information of customer&#39;s Real Application Cluster (RAC)&#39;s SCAN listeners.
     * 
     */
    @Import(name="scanListenerInfos")
    private @Nullable Output<List<OdaPrivateEndpointScanProxyScanListenerInfoArgs>> scanListenerInfos;

    /**
     * @return The FQDN/IPs and port information of customer&#39;s Real Application Cluster (RAC)&#39;s SCAN listeners.
     * 
     */
    public Optional<Output<List<OdaPrivateEndpointScanProxyScanListenerInfoArgs>>> scanListenerInfos() {
        return Optional.ofNullable(this.scanListenerInfos);
    }

    /**
     * Type indicating whether Scan listener is specified by its FQDN or list of IPs
     * 
     */
    @Import(name="scanListenerType")
    private @Nullable Output<String> scanListenerType;

    /**
     * @return Type indicating whether Scan listener is specified by its FQDN or list of IPs
     * 
     */
    public Optional<Output<String>> scanListenerType() {
        return Optional.ofNullable(this.scanListenerType);
    }

    /**
     * The current state of the ODA Private Endpoint Scan Proxy.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the ODA Private Endpoint Scan Proxy.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * When the resource was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return When the resource was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    private OdaPrivateEndpointScanProxyState() {}

    private OdaPrivateEndpointScanProxyState(OdaPrivateEndpointScanProxyState $) {
        this.odaPrivateEndpointId = $.odaPrivateEndpointId;
        this.protocol = $.protocol;
        this.scanListenerInfos = $.scanListenerInfos;
        this.scanListenerType = $.scanListenerType;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(OdaPrivateEndpointScanProxyState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private OdaPrivateEndpointScanProxyState $;

        public Builder() {
            $ = new OdaPrivateEndpointScanProxyState();
        }

        public Builder(OdaPrivateEndpointScanProxyState defaults) {
            $ = new OdaPrivateEndpointScanProxyState(Objects.requireNonNull(defaults));
        }

        /**
         * @param odaPrivateEndpointId Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder odaPrivateEndpointId(@Nullable Output<String> odaPrivateEndpointId) {
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
        public Builder protocol(@Nullable Output<String> protocol) {
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
        public Builder scanListenerInfos(@Nullable Output<List<OdaPrivateEndpointScanProxyScanListenerInfoArgs>> scanListenerInfos) {
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
        public Builder scanListenerType(@Nullable Output<String> scanListenerType) {
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

        /**
         * @param state The current state of the ODA Private Endpoint Scan Proxy.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the ODA Private Endpoint Scan Proxy.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated When the resource was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated When the resource was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        public OdaPrivateEndpointScanProxyState build() {
            return $;
        }
    }

}