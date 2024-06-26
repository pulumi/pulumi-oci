// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class WorkspaceApplicationSourceApplicationInfo {
    /**
     * @return The source application key to use when creating the application.
     * 
     */
    private @Nullable String applicationKey;
    /**
     * @return The source application version of the application.
     * 
     */
    private @Nullable String applicationVersion;
    /**
     * @return Parameter to specify the link between SOURCE and TARGET application after copying. CONNECTED    - Indicate that TARGET application is conneced to SOURCE and can be synced after copy. DISCONNECTED - Indicate that TARGET application is not conneced to SOURCE and can evolve independently.
     * 
     */
    private @Nullable String copyType;
    /**
     * @return The last patch key for the application.
     * 
     */
    private @Nullable String lastPatchKey;
    /**
     * @return The OCID of the workspace containing the application. This allows cross workspace deployment to publish an application from a different workspace into the current workspace specified in this operation.
     * 
     */
    private @Nullable String workspaceId;

    private WorkspaceApplicationSourceApplicationInfo() {}
    /**
     * @return The source application key to use when creating the application.
     * 
     */
    public Optional<String> applicationKey() {
        return Optional.ofNullable(this.applicationKey);
    }
    /**
     * @return The source application version of the application.
     * 
     */
    public Optional<String> applicationVersion() {
        return Optional.ofNullable(this.applicationVersion);
    }
    /**
     * @return Parameter to specify the link between SOURCE and TARGET application after copying. CONNECTED    - Indicate that TARGET application is conneced to SOURCE and can be synced after copy. DISCONNECTED - Indicate that TARGET application is not conneced to SOURCE and can evolve independently.
     * 
     */
    public Optional<String> copyType() {
        return Optional.ofNullable(this.copyType);
    }
    /**
     * @return The last patch key for the application.
     * 
     */
    public Optional<String> lastPatchKey() {
        return Optional.ofNullable(this.lastPatchKey);
    }
    /**
     * @return The OCID of the workspace containing the application. This allows cross workspace deployment to publish an application from a different workspace into the current workspace specified in this operation.
     * 
     */
    public Optional<String> workspaceId() {
        return Optional.ofNullable(this.workspaceId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(WorkspaceApplicationSourceApplicationInfo defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String applicationKey;
        private @Nullable String applicationVersion;
        private @Nullable String copyType;
        private @Nullable String lastPatchKey;
        private @Nullable String workspaceId;
        public Builder() {}
        public Builder(WorkspaceApplicationSourceApplicationInfo defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applicationKey = defaults.applicationKey;
    	      this.applicationVersion = defaults.applicationVersion;
    	      this.copyType = defaults.copyType;
    	      this.lastPatchKey = defaults.lastPatchKey;
    	      this.workspaceId = defaults.workspaceId;
        }

        @CustomType.Setter
        public Builder applicationKey(@Nullable String applicationKey) {

            this.applicationKey = applicationKey;
            return this;
        }
        @CustomType.Setter
        public Builder applicationVersion(@Nullable String applicationVersion) {

            this.applicationVersion = applicationVersion;
            return this;
        }
        @CustomType.Setter
        public Builder copyType(@Nullable String copyType) {

            this.copyType = copyType;
            return this;
        }
        @CustomType.Setter
        public Builder lastPatchKey(@Nullable String lastPatchKey) {

            this.lastPatchKey = lastPatchKey;
            return this;
        }
        @CustomType.Setter
        public Builder workspaceId(@Nullable String workspaceId) {

            this.workspaceId = workspaceId;
            return this;
        }
        public WorkspaceApplicationSourceApplicationInfo build() {
            final var _resultValue = new WorkspaceApplicationSourceApplicationInfo();
            _resultValue.applicationKey = applicationKey;
            _resultValue.applicationVersion = applicationVersion;
            _resultValue.copyType = copyType;
            _resultValue.lastPatchKey = lastPatchKey;
            _resultValue.workspaceId = workspaceId;
            return _resultValue;
        }
    }
}
