// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ScriptParameterScriptParameter {
    /**
     * @return If the parameter value is secret and should be kept confidential, then set isSecret to true.
     * 
     */
    private @Nullable Boolean isSecret;
    /**
     * @return Name of the parameter.
     * 
     */
    private @Nullable String paramName;
    /**
     * @return Value of the parameter.
     * 
     */
    private @Nullable String paramValue;

    private ScriptParameterScriptParameter() {}
    /**
     * @return If the parameter value is secret and should be kept confidential, then set isSecret to true.
     * 
     */
    public Optional<Boolean> isSecret() {
        return Optional.ofNullable(this.isSecret);
    }
    /**
     * @return Name of the parameter.
     * 
     */
    public Optional<String> paramName() {
        return Optional.ofNullable(this.paramName);
    }
    /**
     * @return Value of the parameter.
     * 
     */
    public Optional<String> paramValue() {
        return Optional.ofNullable(this.paramValue);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ScriptParameterScriptParameter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean isSecret;
        private @Nullable String paramName;
        private @Nullable String paramValue;
        public Builder() {}
        public Builder(ScriptParameterScriptParameter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isSecret = defaults.isSecret;
    	      this.paramName = defaults.paramName;
    	      this.paramValue = defaults.paramValue;
        }

        @CustomType.Setter
        public Builder isSecret(@Nullable Boolean isSecret) {

            this.isSecret = isSecret;
            return this;
        }
        @CustomType.Setter
        public Builder paramName(@Nullable String paramName) {

            this.paramName = paramName;
            return this;
        }
        @CustomType.Setter
        public Builder paramValue(@Nullable String paramValue) {

            this.paramValue = paramValue;
            return this;
        }
        public ScriptParameterScriptParameter build() {
            final var _resultValue = new ScriptParameterScriptParameter();
            _resultValue.isSecret = isSecret;
            _resultValue.paramName = paramName;
            _resultValue.paramValue = paramValue;
            return _resultValue;
        }
    }
}
