// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetDataSafeConfigurationGlobalSetting;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetDataSafeConfigurationResult {
    /**
     * @return The OCID of the tenancy used to enable Data Safe.
     * 
     */
    private String compartmentId;
    /**
     * @return The Oracle Data Safe&#39;s NAT Gateway IP Address.
     * 
     */
    private String dataSafeNatGatewayIpAddress;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return Details of the tenancy level global settings in Data Safe.
     * 
     */
    private List<GetDataSafeConfigurationGlobalSetting> globalSettings;
    private String id;
    /**
     * @return Indicates if Data Safe is enabled.
     * 
     */
    private Boolean isEnabled;
    /**
     * @return The current state of Data Safe.
     * 
     */
    private String state;
    /**
     * @return The date and time Data Safe was enabled, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private String timeEnabled;
    /**
     * @return The URL of the Data Safe service.
     * 
     */
    private String url;

    private GetDataSafeConfigurationResult() {}
    /**
     * @return The OCID of the tenancy used to enable Data Safe.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The Oracle Data Safe&#39;s NAT Gateway IP Address.
     * 
     */
    public String dataSafeNatGatewayIpAddress() {
        return this.dataSafeNatGatewayIpAddress;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Details of the tenancy level global settings in Data Safe.
     * 
     */
    public List<GetDataSafeConfigurationGlobalSetting> globalSettings() {
        return this.globalSettings;
    }
    public String id() {
        return this.id;
    }
    /**
     * @return Indicates if Data Safe is enabled.
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }
    /**
     * @return The current state of Data Safe.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time Data Safe was enabled, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timeEnabled() {
        return this.timeEnabled;
    }
    /**
     * @return The URL of the Data Safe service.
     * 
     */
    public String url() {
        return this.url;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDataSafeConfigurationResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String dataSafeNatGatewayIpAddress;
        private Map<String,Object> definedTags;
        private Map<String,Object> freeformTags;
        private List<GetDataSafeConfigurationGlobalSetting> globalSettings;
        private String id;
        private Boolean isEnabled;
        private String state;
        private String timeEnabled;
        private String url;
        public Builder() {}
        public Builder(GetDataSafeConfigurationResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.dataSafeNatGatewayIpAddress = defaults.dataSafeNatGatewayIpAddress;
    	      this.definedTags = defaults.definedTags;
    	      this.freeformTags = defaults.freeformTags;
    	      this.globalSettings = defaults.globalSettings;
    	      this.id = defaults.id;
    	      this.isEnabled = defaults.isEnabled;
    	      this.state = defaults.state;
    	      this.timeEnabled = defaults.timeEnabled;
    	      this.url = defaults.url;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder dataSafeNatGatewayIpAddress(String dataSafeNatGatewayIpAddress) {
            this.dataSafeNatGatewayIpAddress = Objects.requireNonNull(dataSafeNatGatewayIpAddress);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder globalSettings(List<GetDataSafeConfigurationGlobalSetting> globalSettings) {
            this.globalSettings = Objects.requireNonNull(globalSettings);
            return this;
        }
        public Builder globalSettings(GetDataSafeConfigurationGlobalSetting... globalSettings) {
            return globalSettings(List.of(globalSettings));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder isEnabled(Boolean isEnabled) {
            this.isEnabled = Objects.requireNonNull(isEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder timeEnabled(String timeEnabled) {
            this.timeEnabled = Objects.requireNonNull(timeEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder url(String url) {
            this.url = Objects.requireNonNull(url);
            return this;
        }
        public GetDataSafeConfigurationResult build() {
            final var o = new GetDataSafeConfigurationResult();
            o.compartmentId = compartmentId;
            o.dataSafeNatGatewayIpAddress = dataSafeNatGatewayIpAddress;
            o.definedTags = definedTags;
            o.freeformTags = freeformTags;
            o.globalSettings = globalSettings;
            o.id = id;
            o.isEnabled = isEnabled;
            o.state = state;
            o.timeEnabled = timeEnabled;
            o.url = url;
            return o;
        }
    }
}