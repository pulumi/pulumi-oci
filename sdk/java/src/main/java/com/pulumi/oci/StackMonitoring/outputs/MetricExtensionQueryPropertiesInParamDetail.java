// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class MetricExtensionQueryPropertiesInParamDetail {
    /**
     * @return (Updatable) Position of IN parameter
     * 
     */
    private Integer inParamPosition;
    /**
     * @return (Updatable) Value of IN parameter
     * 
     */
    private String inParamValue;

    private MetricExtensionQueryPropertiesInParamDetail() {}
    /**
     * @return (Updatable) Position of IN parameter
     * 
     */
    public Integer inParamPosition() {
        return this.inParamPosition;
    }
    /**
     * @return (Updatable) Value of IN parameter
     * 
     */
    public String inParamValue() {
        return this.inParamValue;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MetricExtensionQueryPropertiesInParamDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer inParamPosition;
        private String inParamValue;
        public Builder() {}
        public Builder(MetricExtensionQueryPropertiesInParamDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.inParamPosition = defaults.inParamPosition;
    	      this.inParamValue = defaults.inParamValue;
        }

        @CustomType.Setter
        public Builder inParamPosition(Integer inParamPosition) {
            this.inParamPosition = Objects.requireNonNull(inParamPosition);
            return this;
        }
        @CustomType.Setter
        public Builder inParamValue(String inParamValue) {
            this.inParamValue = Objects.requireNonNull(inParamValue);
            return this;
        }
        public MetricExtensionQueryPropertiesInParamDetail build() {
            final var o = new MetricExtensionQueryPropertiesInParamDetail();
            o.inParamPosition = inParamPosition;
            o.inParamValue = inParamValue;
            return o;
        }
    }
}