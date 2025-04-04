// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetRuleSetsRuleSetItemCondition {
    /**
     * @return (Required) (Updatable) The attribute_name can be one of these values: `PATH`, `SOURCE_IP_ADDRESS`, `SOURCE_VCN_ID`, `SOURCE_VCN_IP_ADDRESS`
     * 
     */
    private String attributeName;
    /**
     * @return (Required) (Updatable) Depends on `attribute_name`:
     * - when `attribute_name` = `SOURCE_IP_ADDRESS` | IPv4 or IPv6 address range to which the source IP address of incoming packet would be matched against
     * - when `attribute_name` = `SOURCE_VCN_IP_ADDRESS` | IPv4 address range to which the original client IP address (in customer VCN) of incoming packet would be matched against
     * - when `attribute_name` = `SOURCE_VCN_ID` | OCID of the customer VCN to which the service gateway embedded VCN ID of incoming packet would be matched against
     * 
     */
    private String attributeValue;
    /**
     * @return A string that specifies how to compare the PathMatchCondition object&#39;s `attributeValue` string to the incoming URI.
     * *  **EXACT_MATCH** - The incoming URI path must exactly and completely match the `attributeValue` string.
     * *  **FORCE_LONGEST_PREFIX_MATCH** - The system looks for the `attributeValue` string with the best, longest match of the beginning portion of the incoming URI path.
     * *  **PREFIX_MATCH** - The beginning portion of the incoming URI path must exactly match the `attributeValue` string.
     * *  **SUFFIX_MATCH** - The ending portion of the incoming URI path must exactly match the `attributeValue` string.
     * 
     */
    private String operator;

    private GetRuleSetsRuleSetItemCondition() {}
    /**
     * @return (Required) (Updatable) The attribute_name can be one of these values: `PATH`, `SOURCE_IP_ADDRESS`, `SOURCE_VCN_ID`, `SOURCE_VCN_IP_ADDRESS`
     * 
     */
    public String attributeName() {
        return this.attributeName;
    }
    /**
     * @return (Required) (Updatable) Depends on `attribute_name`:
     * - when `attribute_name` = `SOURCE_IP_ADDRESS` | IPv4 or IPv6 address range to which the source IP address of incoming packet would be matched against
     * - when `attribute_name` = `SOURCE_VCN_IP_ADDRESS` | IPv4 address range to which the original client IP address (in customer VCN) of incoming packet would be matched against
     * - when `attribute_name` = `SOURCE_VCN_ID` | OCID of the customer VCN to which the service gateway embedded VCN ID of incoming packet would be matched against
     * 
     */
    public String attributeValue() {
        return this.attributeValue;
    }
    /**
     * @return A string that specifies how to compare the PathMatchCondition object&#39;s `attributeValue` string to the incoming URI.
     * *  **EXACT_MATCH** - The incoming URI path must exactly and completely match the `attributeValue` string.
     * *  **FORCE_LONGEST_PREFIX_MATCH** - The system looks for the `attributeValue` string with the best, longest match of the beginning portion of the incoming URI path.
     * *  **PREFIX_MATCH** - The beginning portion of the incoming URI path must exactly match the `attributeValue` string.
     * *  **SUFFIX_MATCH** - The ending portion of the incoming URI path must exactly match the `attributeValue` string.
     * 
     */
    public String operator() {
        return this.operator;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRuleSetsRuleSetItemCondition defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String attributeName;
        private String attributeValue;
        private String operator;
        public Builder() {}
        public Builder(GetRuleSetsRuleSetItemCondition defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.attributeName = defaults.attributeName;
    	      this.attributeValue = defaults.attributeValue;
    	      this.operator = defaults.operator;
        }

        @CustomType.Setter
        public Builder attributeName(String attributeName) {
            if (attributeName == null) {
              throw new MissingRequiredPropertyException("GetRuleSetsRuleSetItemCondition", "attributeName");
            }
            this.attributeName = attributeName;
            return this;
        }
        @CustomType.Setter
        public Builder attributeValue(String attributeValue) {
            if (attributeValue == null) {
              throw new MissingRequiredPropertyException("GetRuleSetsRuleSetItemCondition", "attributeValue");
            }
            this.attributeValue = attributeValue;
            return this;
        }
        @CustomType.Setter
        public Builder operator(String operator) {
            if (operator == null) {
              throw new MissingRequiredPropertyException("GetRuleSetsRuleSetItemCondition", "operator");
            }
            this.operator = operator;
            return this;
        }
        public GetRuleSetsRuleSetItemCondition build() {
            final var _resultValue = new GetRuleSetsRuleSetItemCondition();
            _resultValue.attributeName = attributeName;
            _resultValue.attributeValue = attributeValue;
            _resultValue.operator = operator;
            return _resultValue;
        }
    }
}
