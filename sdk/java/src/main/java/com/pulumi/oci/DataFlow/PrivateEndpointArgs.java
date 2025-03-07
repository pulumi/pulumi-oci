// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataFlow.inputs.PrivateEndpointScanDetailArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PrivateEndpointArgs extends com.pulumi.resources.ResourceArgs {

    public static final PrivateEndpointArgs Empty = new PrivateEndpointArgs();

    /**
     * (Updatable) The OCID of a compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of a compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A user-friendly description. Avoid entering confidential information.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A user-friendly description. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) A user-friendly name. It does not have to be unique. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. It does not have to be unique. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) An array of DNS zone names. Example: `[ &#34;app.examplecorp.com&#34;, &#34;app.examplecorp2.com&#34; ]`
     * 
     */
    @Import(name="dnsZones", required=true)
    private Output<List<String>> dnsZones;

    /**
     * @return (Updatable) An array of DNS zone names. Example: `[ &#34;app.examplecorp.com&#34;, &#34;app.examplecorp2.com&#34; ]`
     * 
     */
    public Output<List<String>> dnsZones() {
        return this.dnsZones;
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) The maximum number of hosts to be accessed through the private endpoint. This value is used to calculate the relevant CIDR block and should be a multiple of 256.  If the value is not a multiple of 256, it is rounded up to the next multiple of 256. For example, 300 is rounded up to 512.
     * 
     */
    @Import(name="maxHostCount")
    private @Nullable Output<Integer> maxHostCount;

    /**
     * @return (Updatable) The maximum number of hosts to be accessed through the private endpoint. This value is used to calculate the relevant CIDR block and should be a multiple of 256.  If the value is not a multiple of 256, it is rounded up to the next multiple of 256. For example, 300 is rounded up to 512.
     * 
     */
    public Optional<Output<Integer>> maxHostCount() {
        return Optional.ofNullable(this.maxHostCount);
    }

    /**
     * (Updatable) An array of network security group OCIDs.
     * 
     */
    @Import(name="nsgIds")
    private @Nullable Output<List<String>> nsgIds;

    /**
     * @return (Updatable) An array of network security group OCIDs.
     * 
     */
    public Optional<Output<List<String>>> nsgIds() {
        return Optional.ofNullable(this.nsgIds);
    }

    /**
     * (Updatable) An array of fqdn/port pairs used to create private endpoint. Each object is a simple key-value pair with FQDN as key and port number as value. [ { fqdn: &#34;scan1.oracle.com&#34;, port: &#34;1521&#34;}, { fqdn: &#34;scan2.oracle.com&#34;, port: &#34;1521&#34; } ]
     * 
     */
    @Import(name="scanDetails")
    private @Nullable Output<List<PrivateEndpointScanDetailArgs>> scanDetails;

    /**
     * @return (Updatable) An array of fqdn/port pairs used to create private endpoint. Each object is a simple key-value pair with FQDN as key and port number as value. [ { fqdn: &#34;scan1.oracle.com&#34;, port: &#34;1521&#34;}, { fqdn: &#34;scan2.oracle.com&#34;, port: &#34;1521&#34; } ]
     * 
     */
    public Optional<Output<List<PrivateEndpointScanDetailArgs>>> scanDetails() {
        return Optional.ofNullable(this.scanDetails);
    }

    /**
     * The OCID of a subnet.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="subnetId", required=true)
    private Output<String> subnetId;

    /**
     * @return The OCID of a subnet.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> subnetId() {
        return this.subnetId;
    }

    private PrivateEndpointArgs() {}

    private PrivateEndpointArgs(PrivateEndpointArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.dnsZones = $.dnsZones;
        this.freeformTags = $.freeformTags;
        this.maxHostCount = $.maxHostCount;
        this.nsgIds = $.nsgIds;
        this.scanDetails = $.scanDetails;
        this.subnetId = $.subnetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PrivateEndpointArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PrivateEndpointArgs $;

        public Builder() {
            $ = new PrivateEndpointArgs();
        }

        public Builder(PrivateEndpointArgs defaults) {
            $ = new PrivateEndpointArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The OCID of a compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of a compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) A user-friendly description. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A user-friendly description. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) A user-friendly name. It does not have to be unique. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name. It does not have to be unique. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param dnsZones (Updatable) An array of DNS zone names. Example: `[ &#34;app.examplecorp.com&#34;, &#34;app.examplecorp2.com&#34; ]`
         * 
         * @return builder
         * 
         */
        public Builder dnsZones(Output<List<String>> dnsZones) {
            $.dnsZones = dnsZones;
            return this;
        }

        /**
         * @param dnsZones (Updatable) An array of DNS zone names. Example: `[ &#34;app.examplecorp.com&#34;, &#34;app.examplecorp2.com&#34; ]`
         * 
         * @return builder
         * 
         */
        public Builder dnsZones(List<String> dnsZones) {
            return dnsZones(Output.of(dnsZones));
        }

        /**
         * @param dnsZones (Updatable) An array of DNS zone names. Example: `[ &#34;app.examplecorp.com&#34;, &#34;app.examplecorp2.com&#34; ]`
         * 
         * @return builder
         * 
         */
        public Builder dnsZones(String... dnsZones) {
            return dnsZones(List.of(dnsZones));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param maxHostCount (Updatable) The maximum number of hosts to be accessed through the private endpoint. This value is used to calculate the relevant CIDR block and should be a multiple of 256.  If the value is not a multiple of 256, it is rounded up to the next multiple of 256. For example, 300 is rounded up to 512.
         * 
         * @return builder
         * 
         */
        public Builder maxHostCount(@Nullable Output<Integer> maxHostCount) {
            $.maxHostCount = maxHostCount;
            return this;
        }

        /**
         * @param maxHostCount (Updatable) The maximum number of hosts to be accessed through the private endpoint. This value is used to calculate the relevant CIDR block and should be a multiple of 256.  If the value is not a multiple of 256, it is rounded up to the next multiple of 256. For example, 300 is rounded up to 512.
         * 
         * @return builder
         * 
         */
        public Builder maxHostCount(Integer maxHostCount) {
            return maxHostCount(Output.of(maxHostCount));
        }

        /**
         * @param nsgIds (Updatable) An array of network security group OCIDs.
         * 
         * @return builder
         * 
         */
        public Builder nsgIds(@Nullable Output<List<String>> nsgIds) {
            $.nsgIds = nsgIds;
            return this;
        }

        /**
         * @param nsgIds (Updatable) An array of network security group OCIDs.
         * 
         * @return builder
         * 
         */
        public Builder nsgIds(List<String> nsgIds) {
            return nsgIds(Output.of(nsgIds));
        }

        /**
         * @param nsgIds (Updatable) An array of network security group OCIDs.
         * 
         * @return builder
         * 
         */
        public Builder nsgIds(String... nsgIds) {
            return nsgIds(List.of(nsgIds));
        }

        /**
         * @param scanDetails (Updatable) An array of fqdn/port pairs used to create private endpoint. Each object is a simple key-value pair with FQDN as key and port number as value. [ { fqdn: &#34;scan1.oracle.com&#34;, port: &#34;1521&#34;}, { fqdn: &#34;scan2.oracle.com&#34;, port: &#34;1521&#34; } ]
         * 
         * @return builder
         * 
         */
        public Builder scanDetails(@Nullable Output<List<PrivateEndpointScanDetailArgs>> scanDetails) {
            $.scanDetails = scanDetails;
            return this;
        }

        /**
         * @param scanDetails (Updatable) An array of fqdn/port pairs used to create private endpoint. Each object is a simple key-value pair with FQDN as key and port number as value. [ { fqdn: &#34;scan1.oracle.com&#34;, port: &#34;1521&#34;}, { fqdn: &#34;scan2.oracle.com&#34;, port: &#34;1521&#34; } ]
         * 
         * @return builder
         * 
         */
        public Builder scanDetails(List<PrivateEndpointScanDetailArgs> scanDetails) {
            return scanDetails(Output.of(scanDetails));
        }

        /**
         * @param scanDetails (Updatable) An array of fqdn/port pairs used to create private endpoint. Each object is a simple key-value pair with FQDN as key and port number as value. [ { fqdn: &#34;scan1.oracle.com&#34;, port: &#34;1521&#34;}, { fqdn: &#34;scan2.oracle.com&#34;, port: &#34;1521&#34; } ]
         * 
         * @return builder
         * 
         */
        public Builder scanDetails(PrivateEndpointScanDetailArgs... scanDetails) {
            return scanDetails(List.of(scanDetails));
        }

        /**
         * @param subnetId The OCID of a subnet.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder subnetId(Output<String> subnetId) {
            $.subnetId = subnetId;
            return this;
        }

        /**
         * @param subnetId The OCID of a subnet.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder subnetId(String subnetId) {
            return subnetId(Output.of(subnetId));
        }

        public PrivateEndpointArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("PrivateEndpointArgs", "compartmentId");
            }
            if ($.dnsZones == null) {
                throw new MissingRequiredPropertyException("PrivateEndpointArgs", "dnsZones");
            }
            if ($.subnetId == null) {
                throw new MissingRequiredPropertyException("PrivateEndpointArgs", "subnetId");
            }
            return $;
        }
    }

}
