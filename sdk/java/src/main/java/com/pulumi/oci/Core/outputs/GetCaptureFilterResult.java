// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.outputs.GetCaptureFilterFlowLogCaptureFilterRule;
import com.pulumi.oci.Core.outputs.GetCaptureFilterVtapCaptureFilterRule;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetCaptureFilterResult {
    private String captureFilterId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the capture filter.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private String displayName;
    /**
     * @return Indicates which service will use this capture filter
     * 
     */
    private String filterType;
    /**
     * @return The set of rules governing what traffic the Flow Log collects when creating a flow log capture filter.
     * 
     */
    private List<GetCaptureFilterFlowLogCaptureFilterRule> flowLogCaptureFilterRules;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The capture filter&#39;s Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
     * 
     */
    private String id;
    /**
     * @return The capture filter&#39;s current administrative state.
     * 
     */
    private String state;
    /**
     * @return The date and time the capture filter was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2021-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The set of rules governing what traffic a VTAP mirrors.
     * 
     */
    private List<GetCaptureFilterVtapCaptureFilterRule> vtapCaptureFilterRules;

    private GetCaptureFilterResult() {}
    public String captureFilterId() {
        return this.captureFilterId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the capture filter.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Indicates which service will use this capture filter
     * 
     */
    public String filterType() {
        return this.filterType;
    }
    /**
     * @return The set of rules governing what traffic the Flow Log collects when creating a flow log capture filter.
     * 
     */
    public List<GetCaptureFilterFlowLogCaptureFilterRule> flowLogCaptureFilterRules() {
        return this.flowLogCaptureFilterRules;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The capture filter&#39;s Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The capture filter&#39;s current administrative state.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the capture filter was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2021-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The set of rules governing what traffic a VTAP mirrors.
     * 
     */
    public List<GetCaptureFilterVtapCaptureFilterRule> vtapCaptureFilterRules() {
        return this.vtapCaptureFilterRules;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCaptureFilterResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String captureFilterId;
        private String compartmentId;
        private Map<String,String> definedTags;
        private String displayName;
        private String filterType;
        private List<GetCaptureFilterFlowLogCaptureFilterRule> flowLogCaptureFilterRules;
        private Map<String,String> freeformTags;
        private String id;
        private String state;
        private String timeCreated;
        private List<GetCaptureFilterVtapCaptureFilterRule> vtapCaptureFilterRules;
        public Builder() {}
        public Builder(GetCaptureFilterResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.captureFilterId = defaults.captureFilterId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.filterType = defaults.filterType;
    	      this.flowLogCaptureFilterRules = defaults.flowLogCaptureFilterRules;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.vtapCaptureFilterRules = defaults.vtapCaptureFilterRules;
        }

        @CustomType.Setter
        public Builder captureFilterId(String captureFilterId) {
            if (captureFilterId == null) {
              throw new MissingRequiredPropertyException("GetCaptureFilterResult", "captureFilterId");
            }
            this.captureFilterId = captureFilterId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetCaptureFilterResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetCaptureFilterResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetCaptureFilterResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filterType(String filterType) {
            if (filterType == null) {
              throw new MissingRequiredPropertyException("GetCaptureFilterResult", "filterType");
            }
            this.filterType = filterType;
            return this;
        }
        @CustomType.Setter
        public Builder flowLogCaptureFilterRules(List<GetCaptureFilterFlowLogCaptureFilterRule> flowLogCaptureFilterRules) {
            if (flowLogCaptureFilterRules == null) {
              throw new MissingRequiredPropertyException("GetCaptureFilterResult", "flowLogCaptureFilterRules");
            }
            this.flowLogCaptureFilterRules = flowLogCaptureFilterRules;
            return this;
        }
        public Builder flowLogCaptureFilterRules(GetCaptureFilterFlowLogCaptureFilterRule... flowLogCaptureFilterRules) {
            return flowLogCaptureFilterRules(List.of(flowLogCaptureFilterRules));
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetCaptureFilterResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetCaptureFilterResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetCaptureFilterResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetCaptureFilterResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder vtapCaptureFilterRules(List<GetCaptureFilterVtapCaptureFilterRule> vtapCaptureFilterRules) {
            if (vtapCaptureFilterRules == null) {
              throw new MissingRequiredPropertyException("GetCaptureFilterResult", "vtapCaptureFilterRules");
            }
            this.vtapCaptureFilterRules = vtapCaptureFilterRules;
            return this;
        }
        public Builder vtapCaptureFilterRules(GetCaptureFilterVtapCaptureFilterRule... vtapCaptureFilterRules) {
            return vtapCaptureFilterRules(List.of(vtapCaptureFilterRules));
        }
        public GetCaptureFilterResult build() {
            final var _resultValue = new GetCaptureFilterResult();
            _resultValue.captureFilterId = captureFilterId;
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.filterType = filterType;
            _resultValue.flowLogCaptureFilterRules = flowLogCaptureFilterRules;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.vtapCaptureFilterRules = vtapCaptureFilterRules;
            return _resultValue;
        }
    }
}
