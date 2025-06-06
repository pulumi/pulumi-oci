// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.outputs.GetInstancePreemptibleInstanceConfigPreemptionAction;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetInstancePreemptibleInstanceConfig {
    /**
     * @return (Required) The action to run when the preemptible instance is interrupted for eviction.
     * 
     */
    private List<GetInstancePreemptibleInstanceConfigPreemptionAction> preemptionActions;

    private GetInstancePreemptibleInstanceConfig() {}
    /**
     * @return (Required) The action to run when the preemptible instance is interrupted for eviction.
     * 
     */
    public List<GetInstancePreemptibleInstanceConfigPreemptionAction> preemptionActions() {
        return this.preemptionActions;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstancePreemptibleInstanceConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetInstancePreemptibleInstanceConfigPreemptionAction> preemptionActions;
        public Builder() {}
        public Builder(GetInstancePreemptibleInstanceConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.preemptionActions = defaults.preemptionActions;
        }

        @CustomType.Setter
        public Builder preemptionActions(List<GetInstancePreemptibleInstanceConfigPreemptionAction> preemptionActions) {
            if (preemptionActions == null) {
              throw new MissingRequiredPropertyException("GetInstancePreemptibleInstanceConfig", "preemptionActions");
            }
            this.preemptionActions = preemptionActions;
            return this;
        }
        public Builder preemptionActions(GetInstancePreemptibleInstanceConfigPreemptionAction... preemptionActions) {
            return preemptionActions(List.of(preemptionActions));
        }
        public GetInstancePreemptibleInstanceConfig build() {
            final var _resultValue = new GetInstancePreemptibleInstanceConfig();
            _resultValue.preemptionActions = preemptionActions;
            return _resultValue;
        }
    }
}
