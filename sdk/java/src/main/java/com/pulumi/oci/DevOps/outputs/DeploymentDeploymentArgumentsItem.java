// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DeploymentDeploymentArgumentsItem {
    /**
     * @return Name of the parameter (case-sensitive).
     * 
     */
    private @Nullable String name;
    /**
     * @return value of the argument.
     * *  To retrieve Helm Diff for Helm stages in the pipeline add deployment_arguments with name=PLAN_DRY_RUN and value=true
     * 
     */
    private @Nullable String value;

    private DeploymentDeploymentArgumentsItem() {}
    /**
     * @return Name of the parameter (case-sensitive).
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return value of the argument.
     * *  To retrieve Helm Diff for Helm stages in the pipeline add deployment_arguments with name=PLAN_DRY_RUN and value=true
     * 
     */
    public Optional<String> value() {
        return Optional.ofNullable(this.value);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentDeploymentArgumentsItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String name;
        private @Nullable String value;
        public Builder() {}
        public Builder(DeploymentDeploymentArgumentsItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder value(@Nullable String value) {

            this.value = value;
            return this;
        }
        public DeploymentDeploymentArgumentsItem build() {
            final var _resultValue = new DeploymentDeploymentArgumentsItem();
            _resultValue.name = name;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
