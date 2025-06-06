// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class PluggableDatabasesRemoteClonePdbNodeLevelDetail {
    /**
     * @return The Node name of the Database Instance.
     * 
     */
    private @Nullable String nodeName;
    /**
     * @return The mode that pluggable database is in. Open mode can only be changed to READ_ONLY or MIGRATE directly from the backend (within the Oracle Database software).
     * 
     */
    private @Nullable String openMode;

    private PluggableDatabasesRemoteClonePdbNodeLevelDetail() {}
    /**
     * @return The Node name of the Database Instance.
     * 
     */
    public Optional<String> nodeName() {
        return Optional.ofNullable(this.nodeName);
    }
    /**
     * @return The mode that pluggable database is in. Open mode can only be changed to READ_ONLY or MIGRATE directly from the backend (within the Oracle Database software).
     * 
     */
    public Optional<String> openMode() {
        return Optional.ofNullable(this.openMode);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(PluggableDatabasesRemoteClonePdbNodeLevelDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String nodeName;
        private @Nullable String openMode;
        public Builder() {}
        public Builder(PluggableDatabasesRemoteClonePdbNodeLevelDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.nodeName = defaults.nodeName;
    	      this.openMode = defaults.openMode;
        }

        @CustomType.Setter
        public Builder nodeName(@Nullable String nodeName) {

            this.nodeName = nodeName;
            return this;
        }
        @CustomType.Setter
        public Builder openMode(@Nullable String openMode) {

            this.openMode = openMode;
            return this;
        }
        public PluggableDatabasesRemoteClonePdbNodeLevelDetail build() {
            final var _resultValue = new PluggableDatabasesRemoteClonePdbNodeLevelDetail();
            _resultValue.nodeName = nodeName;
            _resultValue.openMode = openMode;
            return _resultValue;
        }
    }
}
