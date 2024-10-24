// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppBundlePoolConfiguration {
    /**
     * @return (Updatable) Maximum number of connector instances in the pool that are idle and active.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: integer
     * * uniqueness: none
     * 
     */
    private @Nullable Integer maxIdle;
    /**
     * @return (Updatable) Maximum number of connector instances in the pool that are idle and active.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: integer
     * * uniqueness: none
     * 
     */
    private @Nullable Integer maxObjects;
    /**
     * @return (Updatable) Maximum time (in milliseconds) to wait for a free connector instance to become available before failing.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: integer
     * * uniqueness: none
     * 
     */
    private @Nullable Integer maxWait;
    /**
     * @return (Updatable) Minimum time (in milliseconds) to wait before evicting an idle conenctor instance from the pool.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: integer
     * * uniqueness: none
     * 
     */
    private @Nullable Integer minEvictableIdleTimeMillis;
    /**
     * @return (Updatable) Minimum number of idle connector instances in the pool.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: integer
     * * uniqueness: none
     * 
     */
    private @Nullable Integer minIdle;

    private DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppBundlePoolConfiguration() {}
    /**
     * @return (Updatable) Maximum number of connector instances in the pool that are idle and active.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: integer
     * * uniqueness: none
     * 
     */
    public Optional<Integer> maxIdle() {
        return Optional.ofNullable(this.maxIdle);
    }
    /**
     * @return (Updatable) Maximum number of connector instances in the pool that are idle and active.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: integer
     * * uniqueness: none
     * 
     */
    public Optional<Integer> maxObjects() {
        return Optional.ofNullable(this.maxObjects);
    }
    /**
     * @return (Updatable) Maximum time (in milliseconds) to wait for a free connector instance to become available before failing.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: integer
     * * uniqueness: none
     * 
     */
    public Optional<Integer> maxWait() {
        return Optional.ofNullable(this.maxWait);
    }
    /**
     * @return (Updatable) Minimum time (in milliseconds) to wait before evicting an idle conenctor instance from the pool.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: integer
     * * uniqueness: none
     * 
     */
    public Optional<Integer> minEvictableIdleTimeMillis() {
        return Optional.ofNullable(this.minEvictableIdleTimeMillis);
    }
    /**
     * @return (Updatable) Minimum number of idle connector instances in the pool.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: integer
     * * uniqueness: none
     * 
     */
    public Optional<Integer> minIdle() {
        return Optional.ofNullable(this.minIdle);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppBundlePoolConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Integer maxIdle;
        private @Nullable Integer maxObjects;
        private @Nullable Integer maxWait;
        private @Nullable Integer minEvictableIdleTimeMillis;
        private @Nullable Integer minIdle;
        public Builder() {}
        public Builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppBundlePoolConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.maxIdle = defaults.maxIdle;
    	      this.maxObjects = defaults.maxObjects;
    	      this.maxWait = defaults.maxWait;
    	      this.minEvictableIdleTimeMillis = defaults.minEvictableIdleTimeMillis;
    	      this.minIdle = defaults.minIdle;
        }

        @CustomType.Setter
        public Builder maxIdle(@Nullable Integer maxIdle) {

            this.maxIdle = maxIdle;
            return this;
        }
        @CustomType.Setter
        public Builder maxObjects(@Nullable Integer maxObjects) {

            this.maxObjects = maxObjects;
            return this;
        }
        @CustomType.Setter
        public Builder maxWait(@Nullable Integer maxWait) {

            this.maxWait = maxWait;
            return this;
        }
        @CustomType.Setter
        public Builder minEvictableIdleTimeMillis(@Nullable Integer minEvictableIdleTimeMillis) {

            this.minEvictableIdleTimeMillis = minEvictableIdleTimeMillis;
            return this;
        }
        @CustomType.Setter
        public Builder minIdle(@Nullable Integer minIdle) {

            this.minIdle = minIdle;
            return this;
        }
        public DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppBundlePoolConfiguration build() {
            final var _resultValue = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppBundlePoolConfiguration();
            _resultValue.maxIdle = maxIdle;
            _resultValue.maxObjects = maxObjects;
            _resultValue.maxWait = maxWait;
            _resultValue.minEvictableIdleTimeMillis = minEvictableIdleTimeMillis;
            _resultValue.minIdle = minIdle;
            return _resultValue;
        }
    }
}
