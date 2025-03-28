// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ObjectStorage.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ObjectStorage.inputs.BucketRetentionRuleArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BucketState extends com.pulumi.resources.ResourceArgs {

    public static final BucketState Empty = new BucketState();

    /**
     * (Updatable) The type of public access enabled on this bucket. A bucket is set to `NoPublicAccess` by default, which only allows an authenticated caller to access the bucket and its contents. When `ObjectRead` is enabled on the bucket, public access is allowed for the `GetObject`, `HeadObject`, and `ListObjects` operations. When `ObjectReadWithoutList` is enabled on the bucket, public access is allowed for the `GetObject` and `HeadObject` operations.
     * 
     */
    @Import(name="accessType")
    private @Nullable Output<String> accessType;

    /**
     * @return (Updatable) The type of public access enabled on this bucket. A bucket is set to `NoPublicAccess` by default, which only allows an authenticated caller to access the bucket and its contents. When `ObjectRead` is enabled on the bucket, public access is allowed for the `GetObject`, `HeadObject`, and `ListObjects` operations. When `ObjectReadWithoutList` is enabled on the bucket, public access is allowed for the `GetObject` and `HeadObject` operations.
     * 
     */
    public Optional<Output<String>> accessType() {
        return Optional.ofNullable(this.accessType);
    }

    /**
     * The approximate number of objects in the bucket. Count statistics are reported periodically. You will see a lag between what is displayed and the actual object count.
     * 
     */
    @Import(name="approximateCount")
    private @Nullable Output<String> approximateCount;

    /**
     * @return The approximate number of objects in the bucket. Count statistics are reported periodically. You will see a lag between what is displayed and the actual object count.
     * 
     */
    public Optional<Output<String>> approximateCount() {
        return Optional.ofNullable(this.approximateCount);
    }

    /**
     * The approximate total size in bytes of all objects in the bucket. Size statistics are reported periodically. You will see a lag between what is displayed and the actual size of the bucket.
     * 
     */
    @Import(name="approximateSize")
    private @Nullable Output<String> approximateSize;

    /**
     * @return The approximate total size in bytes of all objects in the bucket. Size statistics are reported periodically. You will see a lag between what is displayed and the actual size of the bucket.
     * 
     */
    public Optional<Output<String>> approximateSize() {
        return Optional.ofNullable(this.approximateSize);
    }

    /**
     * (Updatable) Set the auto tiering status on the bucket. By default, a bucket is created with auto tiering `Disabled`. Use this option to enable auto tiering during bucket creation. Objects in a bucket with auto tiering set to `InfrequentAccess` are transitioned automatically between the &#39;Standard&#39; and &#39;InfrequentAccess&#39; tiers based on the access pattern of the objects.
     * 
     */
    @Import(name="autoTiering")
    private @Nullable Output<String> autoTiering;

    /**
     * @return (Updatable) Set the auto tiering status on the bucket. By default, a bucket is created with auto tiering `Disabled`. Use this option to enable auto tiering during bucket creation. Objects in a bucket with auto tiering set to `InfrequentAccess` are transitioned automatically between the &#39;Standard&#39; and &#39;InfrequentAccess&#39; tiers based on the access pattern of the objects.
     * 
     */
    public Optional<Output<String>> autoTiering() {
        return Optional.ofNullable(this.autoTiering);
    }

    /**
     * The OCID of the bucket which is a Oracle assigned unique identifier for this resource type (bucket). `bucket_id` cannot be used for bucket lookup.
     * 
     */
    @Import(name="bucketId")
    private @Nullable Output<String> bucketId;

    /**
     * @return The OCID of the bucket which is a Oracle assigned unique identifier for this resource type (bucket). `bucket_id` cannot be used for bucket lookup.
     * 
     */
    public Optional<Output<String>> bucketId() {
        return Optional.ofNullable(this.bucketId);
    }

    /**
     * (Updatable) The ID of the compartment in which to create the bucket.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The ID of the compartment in which to create the bucket.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the bucket.
     * 
     */
    @Import(name="createdBy")
    private @Nullable Output<String> createdBy;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the bucket.
     * 
     */
    public Optional<Output<String>> createdBy() {
        return Optional.ofNullable(this.createdBy);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * The entity tag (ETag) for the bucket.
     * 
     */
    @Import(name="etag")
    private @Nullable Output<String> etag;

    /**
     * @return The entity tag (ETag) for the bucket.
     * 
     */
    public Optional<Output<String>> etag() {
        return Optional.ofNullable(this.etag);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * Whether or not this bucket is read only. By default, `isReadOnly` is set to `false`. This will be set to &#39;true&#39; when this bucket is configured as a destination in a replication policy.
     * 
     */
    @Import(name="isReadOnly")
    private @Nullable Output<Boolean> isReadOnly;

    /**
     * @return Whether or not this bucket is read only. By default, `isReadOnly` is set to `false`. This will be set to &#39;true&#39; when this bucket is configured as a destination in a replication policy.
     * 
     */
    public Optional<Output<Boolean>> isReadOnly() {
        return Optional.ofNullable(this.isReadOnly);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a master encryption key used to call the Key Management service to generate a data encryption key or to encrypt or decrypt a data encryption key.
     * 
     */
    @Import(name="kmsKeyId")
    private @Nullable Output<String> kmsKeyId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a master encryption key used to call the Key Management service to generate a data encryption key or to encrypt or decrypt a data encryption key.
     * 
     */
    public Optional<Output<String>> kmsKeyId() {
        return Optional.ofNullable(this.kmsKeyId);
    }

    /**
     * (Updatable) Arbitrary string, up to 4KB, of keys and values for user-defined metadata.
     * 
     */
    @Import(name="metadata")
    private @Nullable Output<Map<String,String>> metadata;

    /**
     * @return (Updatable) Arbitrary string, up to 4KB, of keys and values for user-defined metadata.
     * 
     */
    public Optional<Output<Map<String,String>>> metadata() {
        return Optional.ofNullable(this.metadata);
    }

    /**
     * The name of the bucket. Valid characters are uppercase or lowercase letters, numbers, hyphens, underscores, and periods. Bucket names must be unique within an Object Storage namespace. Avoid entering confidential information. example: Example: my-new-bucket1
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return The name of the bucket. Valid characters are uppercase or lowercase letters, numbers, hyphens, underscores, and periods. Bucket names must be unique within an Object Storage namespace. Avoid entering confidential information. example: Example: my-new-bucket1
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The Object Storage namespace used for the request.
     * 
     */
    @Import(name="namespace")
    private @Nullable Output<String> namespace;

    /**
     * @return The Object Storage namespace used for the request.
     * 
     */
    public Optional<Output<String>> namespace() {
        return Optional.ofNullable(this.namespace);
    }

    /**
     * (Updatable) Whether or not events are emitted for object state changes in this bucket. By default, `objectEventsEnabled` is set to `false`. Set `objectEventsEnabled` to `true` to emit events for object state changes. For more information about events, see [Overview of Events](https://docs.cloud.oracle.com/iaas/Content/Events/Concepts/eventsoverview.htm).
     * 
     */
    @Import(name="objectEventsEnabled")
    private @Nullable Output<Boolean> objectEventsEnabled;

    /**
     * @return (Updatable) Whether or not events are emitted for object state changes in this bucket. By default, `objectEventsEnabled` is set to `false`. Set `objectEventsEnabled` to `true` to emit events for object state changes. For more information about events, see [Overview of Events](https://docs.cloud.oracle.com/iaas/Content/Events/Concepts/eventsoverview.htm).
     * 
     */
    public Optional<Output<Boolean>> objectEventsEnabled() {
        return Optional.ofNullable(this.objectEventsEnabled);
    }

    /**
     * The entity tag (ETag) for the live object lifecycle policy on the bucket.
     * 
     */
    @Import(name="objectLifecyclePolicyEtag")
    private @Nullable Output<String> objectLifecyclePolicyEtag;

    /**
     * @return The entity tag (ETag) for the live object lifecycle policy on the bucket.
     * 
     */
    public Optional<Output<String>> objectLifecyclePolicyEtag() {
        return Optional.ofNullable(this.objectLifecyclePolicyEtag);
    }

    /**
     * Whether or not this bucket is a replication source. By default, `replicationEnabled` is set to `false`. This will be set to &#39;true&#39; when you create a replication policy for the bucket.
     * 
     */
    @Import(name="replicationEnabled")
    private @Nullable Output<Boolean> replicationEnabled;

    /**
     * @return Whether or not this bucket is a replication source. By default, `replicationEnabled` is set to `false`. This will be set to &#39;true&#39; when you create a replication policy for the bucket.
     * 
     */
    public Optional<Output<Boolean>> replicationEnabled() {
        return Optional.ofNullable(this.replicationEnabled);
    }

    /**
     * (Updatable) Creates a new retention rule in the specified bucket. The new rule will take effect typically within 30 seconds. Note that a maximum of 100 rules are supported on a bucket.
     * 
     */
    @Import(name="retentionRules")
    private @Nullable Output<List<BucketRetentionRuleArgs>> retentionRules;

    /**
     * @return (Updatable) Creates a new retention rule in the specified bucket. The new rule will take effect typically within 30 seconds. Note that a maximum of 100 rules are supported on a bucket.
     * 
     */
    public Optional<Output<List<BucketRetentionRuleArgs>>> retentionRules() {
        return Optional.ofNullable(this.retentionRules);
    }

    /**
     * The type of storage tier of this bucket. A bucket is set to &#39;Standard&#39; tier by default, which means the bucket will be put in the standard storage tier. When &#39;Archive&#39; tier type is set explicitly, the bucket is put in the Archive Storage tier. The &#39;storageTier&#39; property is immutable after bucket is created.
     * 
     */
    @Import(name="storageTier")
    private @Nullable Output<String> storageTier;

    /**
     * @return The type of storage tier of this bucket. A bucket is set to &#39;Standard&#39; tier by default, which means the bucket will be put in the standard storage tier. When &#39;Archive&#39; tier type is set explicitly, the bucket is put in the Archive Storage tier. The &#39;storageTier&#39; property is immutable after bucket is created.
     * 
     */
    public Optional<Output<String>> storageTier() {
        return Optional.ofNullable(this.storageTier);
    }

    /**
     * The date and time the bucket was created, as described in [RFC 2616](https://tools.ietf.org/html/rfc2616#section-14.29).
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the bucket was created, as described in [RFC 2616](https://tools.ietf.org/html/rfc2616#section-14.29).
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * (Updatable) Set the versioning status on the bucket. By default, a bucket is created with versioning `Disabled`. Use this option to enable versioning during bucket creation. Objects in a version enabled bucket are protected from overwrites and deletions. Previous versions of the same object will be available in the bucket. Allowed Create values: Enabled, Disabled. Allowed Update values: Enabled, Suspended.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="versioning")
    private @Nullable Output<String> versioning;

    /**
     * @return (Updatable) Set the versioning status on the bucket. By default, a bucket is created with versioning `Disabled`. Use this option to enable versioning during bucket creation. Objects in a version enabled bucket are protected from overwrites and deletions. Previous versions of the same object will be available in the bucket. Allowed Create values: Enabled, Disabled. Allowed Update values: Enabled, Suspended.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> versioning() {
        return Optional.ofNullable(this.versioning);
    }

    private BucketState() {}

    private BucketState(BucketState $) {
        this.accessType = $.accessType;
        this.approximateCount = $.approximateCount;
        this.approximateSize = $.approximateSize;
        this.autoTiering = $.autoTiering;
        this.bucketId = $.bucketId;
        this.compartmentId = $.compartmentId;
        this.createdBy = $.createdBy;
        this.definedTags = $.definedTags;
        this.etag = $.etag;
        this.freeformTags = $.freeformTags;
        this.isReadOnly = $.isReadOnly;
        this.kmsKeyId = $.kmsKeyId;
        this.metadata = $.metadata;
        this.name = $.name;
        this.namespace = $.namespace;
        this.objectEventsEnabled = $.objectEventsEnabled;
        this.objectLifecyclePolicyEtag = $.objectLifecyclePolicyEtag;
        this.replicationEnabled = $.replicationEnabled;
        this.retentionRules = $.retentionRules;
        this.storageTier = $.storageTier;
        this.timeCreated = $.timeCreated;
        this.versioning = $.versioning;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BucketState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BucketState $;

        public Builder() {
            $ = new BucketState();
        }

        public Builder(BucketState defaults) {
            $ = new BucketState(Objects.requireNonNull(defaults));
        }

        /**
         * @param accessType (Updatable) The type of public access enabled on this bucket. A bucket is set to `NoPublicAccess` by default, which only allows an authenticated caller to access the bucket and its contents. When `ObjectRead` is enabled on the bucket, public access is allowed for the `GetObject`, `HeadObject`, and `ListObjects` operations. When `ObjectReadWithoutList` is enabled on the bucket, public access is allowed for the `GetObject` and `HeadObject` operations.
         * 
         * @return builder
         * 
         */
        public Builder accessType(@Nullable Output<String> accessType) {
            $.accessType = accessType;
            return this;
        }

        /**
         * @param accessType (Updatable) The type of public access enabled on this bucket. A bucket is set to `NoPublicAccess` by default, which only allows an authenticated caller to access the bucket and its contents. When `ObjectRead` is enabled on the bucket, public access is allowed for the `GetObject`, `HeadObject`, and `ListObjects` operations. When `ObjectReadWithoutList` is enabled on the bucket, public access is allowed for the `GetObject` and `HeadObject` operations.
         * 
         * @return builder
         * 
         */
        public Builder accessType(String accessType) {
            return accessType(Output.of(accessType));
        }

        /**
         * @param approximateCount The approximate number of objects in the bucket. Count statistics are reported periodically. You will see a lag between what is displayed and the actual object count.
         * 
         * @return builder
         * 
         */
        public Builder approximateCount(@Nullable Output<String> approximateCount) {
            $.approximateCount = approximateCount;
            return this;
        }

        /**
         * @param approximateCount The approximate number of objects in the bucket. Count statistics are reported periodically. You will see a lag between what is displayed and the actual object count.
         * 
         * @return builder
         * 
         */
        public Builder approximateCount(String approximateCount) {
            return approximateCount(Output.of(approximateCount));
        }

        /**
         * @param approximateSize The approximate total size in bytes of all objects in the bucket. Size statistics are reported periodically. You will see a lag between what is displayed and the actual size of the bucket.
         * 
         * @return builder
         * 
         */
        public Builder approximateSize(@Nullable Output<String> approximateSize) {
            $.approximateSize = approximateSize;
            return this;
        }

        /**
         * @param approximateSize The approximate total size in bytes of all objects in the bucket. Size statistics are reported periodically. You will see a lag between what is displayed and the actual size of the bucket.
         * 
         * @return builder
         * 
         */
        public Builder approximateSize(String approximateSize) {
            return approximateSize(Output.of(approximateSize));
        }

        /**
         * @param autoTiering (Updatable) Set the auto tiering status on the bucket. By default, a bucket is created with auto tiering `Disabled`. Use this option to enable auto tiering during bucket creation. Objects in a bucket with auto tiering set to `InfrequentAccess` are transitioned automatically between the &#39;Standard&#39; and &#39;InfrequentAccess&#39; tiers based on the access pattern of the objects.
         * 
         * @return builder
         * 
         */
        public Builder autoTiering(@Nullable Output<String> autoTiering) {
            $.autoTiering = autoTiering;
            return this;
        }

        /**
         * @param autoTiering (Updatable) Set the auto tiering status on the bucket. By default, a bucket is created with auto tiering `Disabled`. Use this option to enable auto tiering during bucket creation. Objects in a bucket with auto tiering set to `InfrequentAccess` are transitioned automatically between the &#39;Standard&#39; and &#39;InfrequentAccess&#39; tiers based on the access pattern of the objects.
         * 
         * @return builder
         * 
         */
        public Builder autoTiering(String autoTiering) {
            return autoTiering(Output.of(autoTiering));
        }

        /**
         * @param bucketId The OCID of the bucket which is a Oracle assigned unique identifier for this resource type (bucket). `bucket_id` cannot be used for bucket lookup.
         * 
         * @return builder
         * 
         */
        public Builder bucketId(@Nullable Output<String> bucketId) {
            $.bucketId = bucketId;
            return this;
        }

        /**
         * @param bucketId The OCID of the bucket which is a Oracle assigned unique identifier for this resource type (bucket). `bucket_id` cannot be used for bucket lookup.
         * 
         * @return builder
         * 
         */
        public Builder bucketId(String bucketId) {
            return bucketId(Output.of(bucketId));
        }

        /**
         * @param compartmentId (Updatable) The ID of the compartment in which to create the bucket.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The ID of the compartment in which to create the bucket.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param createdBy The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the bucket.
         * 
         * @return builder
         * 
         */
        public Builder createdBy(@Nullable Output<String> createdBy) {
            $.createdBy = createdBy;
            return this;
        }

        /**
         * @param createdBy The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the bucket.
         * 
         * @return builder
         * 
         */
        public Builder createdBy(String createdBy) {
            return createdBy(Output.of(createdBy));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param etag The entity tag (ETag) for the bucket.
         * 
         * @return builder
         * 
         */
        public Builder etag(@Nullable Output<String> etag) {
            $.etag = etag;
            return this;
        }

        /**
         * @param etag The entity tag (ETag) for the bucket.
         * 
         * @return builder
         * 
         */
        public Builder etag(String etag) {
            return etag(Output.of(etag));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isReadOnly Whether or not this bucket is read only. By default, `isReadOnly` is set to `false`. This will be set to &#39;true&#39; when this bucket is configured as a destination in a replication policy.
         * 
         * @return builder
         * 
         */
        public Builder isReadOnly(@Nullable Output<Boolean> isReadOnly) {
            $.isReadOnly = isReadOnly;
            return this;
        }

        /**
         * @param isReadOnly Whether or not this bucket is read only. By default, `isReadOnly` is set to `false`. This will be set to &#39;true&#39; when this bucket is configured as a destination in a replication policy.
         * 
         * @return builder
         * 
         */
        public Builder isReadOnly(Boolean isReadOnly) {
            return isReadOnly(Output.of(isReadOnly));
        }

        /**
         * @param kmsKeyId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a master encryption key used to call the Key Management service to generate a data encryption key or to encrypt or decrypt a data encryption key.
         * 
         * @return builder
         * 
         */
        public Builder kmsKeyId(@Nullable Output<String> kmsKeyId) {
            $.kmsKeyId = kmsKeyId;
            return this;
        }

        /**
         * @param kmsKeyId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a master encryption key used to call the Key Management service to generate a data encryption key or to encrypt or decrypt a data encryption key.
         * 
         * @return builder
         * 
         */
        public Builder kmsKeyId(String kmsKeyId) {
            return kmsKeyId(Output.of(kmsKeyId));
        }

        /**
         * @param metadata (Updatable) Arbitrary string, up to 4KB, of keys and values for user-defined metadata.
         * 
         * @return builder
         * 
         */
        public Builder metadata(@Nullable Output<Map<String,String>> metadata) {
            $.metadata = metadata;
            return this;
        }

        /**
         * @param metadata (Updatable) Arbitrary string, up to 4KB, of keys and values for user-defined metadata.
         * 
         * @return builder
         * 
         */
        public Builder metadata(Map<String,String> metadata) {
            return metadata(Output.of(metadata));
        }

        /**
         * @param name The name of the bucket. Valid characters are uppercase or lowercase letters, numbers, hyphens, underscores, and periods. Bucket names must be unique within an Object Storage namespace. Avoid entering confidential information. example: Example: my-new-bucket1
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name The name of the bucket. Valid characters are uppercase or lowercase letters, numbers, hyphens, underscores, and periods. Bucket names must be unique within an Object Storage namespace. Avoid entering confidential information. example: Example: my-new-bucket1
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param namespace The Object Storage namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(@Nullable Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace The Object Storage namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param objectEventsEnabled (Updatable) Whether or not events are emitted for object state changes in this bucket. By default, `objectEventsEnabled` is set to `false`. Set `objectEventsEnabled` to `true` to emit events for object state changes. For more information about events, see [Overview of Events](https://docs.cloud.oracle.com/iaas/Content/Events/Concepts/eventsoverview.htm).
         * 
         * @return builder
         * 
         */
        public Builder objectEventsEnabled(@Nullable Output<Boolean> objectEventsEnabled) {
            $.objectEventsEnabled = objectEventsEnabled;
            return this;
        }

        /**
         * @param objectEventsEnabled (Updatable) Whether or not events are emitted for object state changes in this bucket. By default, `objectEventsEnabled` is set to `false`. Set `objectEventsEnabled` to `true` to emit events for object state changes. For more information about events, see [Overview of Events](https://docs.cloud.oracle.com/iaas/Content/Events/Concepts/eventsoverview.htm).
         * 
         * @return builder
         * 
         */
        public Builder objectEventsEnabled(Boolean objectEventsEnabled) {
            return objectEventsEnabled(Output.of(objectEventsEnabled));
        }

        /**
         * @param objectLifecyclePolicyEtag The entity tag (ETag) for the live object lifecycle policy on the bucket.
         * 
         * @return builder
         * 
         */
        public Builder objectLifecyclePolicyEtag(@Nullable Output<String> objectLifecyclePolicyEtag) {
            $.objectLifecyclePolicyEtag = objectLifecyclePolicyEtag;
            return this;
        }

        /**
         * @param objectLifecyclePolicyEtag The entity tag (ETag) for the live object lifecycle policy on the bucket.
         * 
         * @return builder
         * 
         */
        public Builder objectLifecyclePolicyEtag(String objectLifecyclePolicyEtag) {
            return objectLifecyclePolicyEtag(Output.of(objectLifecyclePolicyEtag));
        }

        /**
         * @param replicationEnabled Whether or not this bucket is a replication source. By default, `replicationEnabled` is set to `false`. This will be set to &#39;true&#39; when you create a replication policy for the bucket.
         * 
         * @return builder
         * 
         */
        public Builder replicationEnabled(@Nullable Output<Boolean> replicationEnabled) {
            $.replicationEnabled = replicationEnabled;
            return this;
        }

        /**
         * @param replicationEnabled Whether or not this bucket is a replication source. By default, `replicationEnabled` is set to `false`. This will be set to &#39;true&#39; when you create a replication policy for the bucket.
         * 
         * @return builder
         * 
         */
        public Builder replicationEnabled(Boolean replicationEnabled) {
            return replicationEnabled(Output.of(replicationEnabled));
        }

        /**
         * @param retentionRules (Updatable) Creates a new retention rule in the specified bucket. The new rule will take effect typically within 30 seconds. Note that a maximum of 100 rules are supported on a bucket.
         * 
         * @return builder
         * 
         */
        public Builder retentionRules(@Nullable Output<List<BucketRetentionRuleArgs>> retentionRules) {
            $.retentionRules = retentionRules;
            return this;
        }

        /**
         * @param retentionRules (Updatable) Creates a new retention rule in the specified bucket. The new rule will take effect typically within 30 seconds. Note that a maximum of 100 rules are supported on a bucket.
         * 
         * @return builder
         * 
         */
        public Builder retentionRules(List<BucketRetentionRuleArgs> retentionRules) {
            return retentionRules(Output.of(retentionRules));
        }

        /**
         * @param retentionRules (Updatable) Creates a new retention rule in the specified bucket. The new rule will take effect typically within 30 seconds. Note that a maximum of 100 rules are supported on a bucket.
         * 
         * @return builder
         * 
         */
        public Builder retentionRules(BucketRetentionRuleArgs... retentionRules) {
            return retentionRules(List.of(retentionRules));
        }

        /**
         * @param storageTier The type of storage tier of this bucket. A bucket is set to &#39;Standard&#39; tier by default, which means the bucket will be put in the standard storage tier. When &#39;Archive&#39; tier type is set explicitly, the bucket is put in the Archive Storage tier. The &#39;storageTier&#39; property is immutable after bucket is created.
         * 
         * @return builder
         * 
         */
        public Builder storageTier(@Nullable Output<String> storageTier) {
            $.storageTier = storageTier;
            return this;
        }

        /**
         * @param storageTier The type of storage tier of this bucket. A bucket is set to &#39;Standard&#39; tier by default, which means the bucket will be put in the standard storage tier. When &#39;Archive&#39; tier type is set explicitly, the bucket is put in the Archive Storage tier. The &#39;storageTier&#39; property is immutable after bucket is created.
         * 
         * @return builder
         * 
         */
        public Builder storageTier(String storageTier) {
            return storageTier(Output.of(storageTier));
        }

        /**
         * @param timeCreated The date and time the bucket was created, as described in [RFC 2616](https://tools.ietf.org/html/rfc2616#section-14.29).
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the bucket was created, as described in [RFC 2616](https://tools.ietf.org/html/rfc2616#section-14.29).
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param versioning (Updatable) Set the versioning status on the bucket. By default, a bucket is created with versioning `Disabled`. Use this option to enable versioning during bucket creation. Objects in a version enabled bucket are protected from overwrites and deletions. Previous versions of the same object will be available in the bucket. Allowed Create values: Enabled, Disabled. Allowed Update values: Enabled, Suspended.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder versioning(@Nullable Output<String> versioning) {
            $.versioning = versioning;
            return this;
        }

        /**
         * @param versioning (Updatable) Set the versioning status on the bucket. By default, a bucket is created with versioning `Disabled`. Use this option to enable versioning during bucket creation. Objects in a version enabled bucket are protected from overwrites and deletions. Previous versions of the same object will be available in the bucket. Allowed Create values: Enabled, Disabled. Allowed Update values: Enabled, Suspended.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder versioning(String versioning) {
            return versioning(Output.of(versioning));
        }

        public BucketState build() {
            return $;
        }
    }

}
