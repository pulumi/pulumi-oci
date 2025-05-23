// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.util.Objects;

@CustomType
public final class GetScriptMonitorStatusCountMap {
    /**
     * @return Number of disabled monitors using the script.
     * 
     */
    private Integer disabled;
    /**
     * @return Number of enabled monitors using the script.
     * 
     */
    private Integer enabled;
    /**
     * @return Number of invalid monitors using the script.
     * 
     */
    private Integer invalid;
    /**
     * @return Total number of monitors using the script.
     * 
     */
    private Integer total;

    private GetScriptMonitorStatusCountMap() {}
    /**
     * @return Number of disabled monitors using the script.
     * 
     */
    public Integer disabled() {
        return this.disabled;
    }
    /**
     * @return Number of enabled monitors using the script.
     * 
     */
    public Integer enabled() {
        return this.enabled;
    }
    /**
     * @return Number of invalid monitors using the script.
     * 
     */
    public Integer invalid() {
        return this.invalid;
    }
    /**
     * @return Total number of monitors using the script.
     * 
     */
    public Integer total() {
        return this.total;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetScriptMonitorStatusCountMap defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer disabled;
        private Integer enabled;
        private Integer invalid;
        private Integer total;
        public Builder() {}
        public Builder(GetScriptMonitorStatusCountMap defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.disabled = defaults.disabled;
    	      this.enabled = defaults.enabled;
    	      this.invalid = defaults.invalid;
    	      this.total = defaults.total;
        }

        @CustomType.Setter
        public Builder disabled(Integer disabled) {
            if (disabled == null) {
              throw new MissingRequiredPropertyException("GetScriptMonitorStatusCountMap", "disabled");
            }
            this.disabled = disabled;
            return this;
        }
        @CustomType.Setter
        public Builder enabled(Integer enabled) {
            if (enabled == null) {
              throw new MissingRequiredPropertyException("GetScriptMonitorStatusCountMap", "enabled");
            }
            this.enabled = enabled;
            return this;
        }
        @CustomType.Setter
        public Builder invalid(Integer invalid) {
            if (invalid == null) {
              throw new MissingRequiredPropertyException("GetScriptMonitorStatusCountMap", "invalid");
            }
            this.invalid = invalid;
            return this;
        }
        @CustomType.Setter
        public Builder total(Integer total) {
            if (total == null) {
              throw new MissingRequiredPropertyException("GetScriptMonitorStatusCountMap", "total");
            }
            this.total = total;
            return this;
        }
        public GetScriptMonitorStatusCountMap build() {
            final var _resultValue = new GetScriptMonitorStatusCountMap();
            _resultValue.disabled = disabled;
            _resultValue.enabled = enabled;
            _resultValue.invalid = invalid;
            _resultValue.total = total;
            return _resultValue;
        }
    }
}
