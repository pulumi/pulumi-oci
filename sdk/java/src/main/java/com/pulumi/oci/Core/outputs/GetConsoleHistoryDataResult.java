// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetConsoleHistoryDataResult {
    private String consoleHistoryId;
    /**
     * @return The console history data.
     * 
     */
    private String data;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable Integer length;
    private @Nullable Integer offset;

    private GetConsoleHistoryDataResult() {}
    public String consoleHistoryId() {
        return this.consoleHistoryId;
    }
    /**
     * @return The console history data.
     * 
     */
    public String data() {
        return this.data;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<Integer> length() {
        return Optional.ofNullable(this.length);
    }
    public Optional<Integer> offset() {
        return Optional.ofNullable(this.offset);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetConsoleHistoryDataResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String consoleHistoryId;
        private String data;
        private String id;
        private @Nullable Integer length;
        private @Nullable Integer offset;
        public Builder() {}
        public Builder(GetConsoleHistoryDataResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.consoleHistoryId = defaults.consoleHistoryId;
    	      this.data = defaults.data;
    	      this.id = defaults.id;
    	      this.length = defaults.length;
    	      this.offset = defaults.offset;
        }

        @CustomType.Setter
        public Builder consoleHistoryId(String consoleHistoryId) {
            this.consoleHistoryId = Objects.requireNonNull(consoleHistoryId);
            return this;
        }
        @CustomType.Setter
        public Builder data(String data) {
            this.data = Objects.requireNonNull(data);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder length(@Nullable Integer length) {
            this.length = length;
            return this;
        }
        @CustomType.Setter
        public Builder offset(@Nullable Integer offset) {
            this.offset = offset;
            return this;
        }
        public GetConsoleHistoryDataResult build() {
            final var o = new GetConsoleHistoryDataResult();
            o.consoleHistoryId = consoleHistoryId;
            o.data = data;
            o.id = id;
            o.length = length;
            o.offset = offset;
            return o;
        }
    }
}