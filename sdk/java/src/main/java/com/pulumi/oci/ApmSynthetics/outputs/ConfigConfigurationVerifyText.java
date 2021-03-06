// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ConfigConfigurationVerifyText {
    /**
     * @return (Updatable) Verification text in the response.
     * 
     */
    private final @Nullable String text;

    @CustomType.Constructor
    private ConfigConfigurationVerifyText(@CustomType.Parameter("text") @Nullable String text) {
        this.text = text;
    }

    /**
     * @return (Updatable) Verification text in the response.
     * 
     */
    public Optional<String> text() {
        return Optional.ofNullable(this.text);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ConfigConfigurationVerifyText defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String text;

        public Builder() {
    	      // Empty
        }

        public Builder(ConfigConfigurationVerifyText defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.text = defaults.text;
        }

        public Builder text(@Nullable String text) {
            this.text = text;
            return this;
        }        public ConfigConfigurationVerifyText build() {
            return new ConfigConfigurationVerifyText(text);
        }
    }
}
