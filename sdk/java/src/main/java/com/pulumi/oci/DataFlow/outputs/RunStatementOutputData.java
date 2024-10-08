// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class RunStatementOutputData {
    /**
     * @return The type of the `StatementOutputData` like `TEXT_PLAIN`, `TEXT_HTML` or `IMAGE_PNG`.
     * 
     */
    private @Nullable String type;
    /**
     * @return The statement code execution output in html format.
     * 
     */
    private @Nullable String value;

    private RunStatementOutputData() {}
    /**
     * @return The type of the `StatementOutputData` like `TEXT_PLAIN`, `TEXT_HTML` or `IMAGE_PNG`.
     * 
     */
    public Optional<String> type() {
        return Optional.ofNullable(this.type);
    }
    /**
     * @return The statement code execution output in html format.
     * 
     */
    public Optional<String> value() {
        return Optional.ofNullable(this.value);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(RunStatementOutputData defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String type;
        private @Nullable String value;
        public Builder() {}
        public Builder(RunStatementOutputData defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.type = defaults.type;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder type(@Nullable String type) {

            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder value(@Nullable String value) {

            this.value = value;
            return this;
        }
        public RunStatementOutputData build() {
            final var _resultValue = new RunStatementOutputData();
            _resultValue.type = type;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
