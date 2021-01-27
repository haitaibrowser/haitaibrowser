/*
 * Copyright 2015 Google Inc.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef GrVkImage_DEFINED
#define GrVkImage_DEFINED

#include "GrVkResource.h"

#include "GrTypesPriv.h"
#include "SkTypes.h"

#include "vk/GrVkDefines.h"
#include "vk/GrVkTypes.h"

class GrVkGpu;

class GrVkImage : SkNoncopyable {
private:
    class Resource;

public:
    enum Wrapped {
        kNot_Wrapped,
        kAdopted_Wrapped,
        kBorrowed_Wrapped,
    };

    GrVkImage(const GrVkImageInfo& info, Wrapped wrapped)
        : fInfo(info)
        , fIsBorrowed(kBorrowed_Wrapped == wrapped) {
        if (kBorrowed_Wrapped == wrapped) {
            fResource = new BorrowedResource(info.fImage, info.fAlloc);
        } else {
            fResource = new Resource(info.fImage, info.fAlloc);
        }
    }
    virtual ~GrVkImage();

    VkImage image() const { return fInfo.fImage; }
    VkDeviceMemory memory() const { return fInfo.fAlloc; }
    VkFormat imageFormat() const { return fInfo.fFormat; }
    const Resource* resource() const { return fResource; }
    bool isLinearTiled() const {
        return SkToBool(VK_IMAGE_TILING_LINEAR == fInfo.fImageTiling);
    }

    VkImageLayout currentLayout() const { return fInfo.fImageLayout; }

    void setImageLayout(const GrVkGpu* gpu,
                        VkImageLayout newLayout,
                        VkAccessFlags dstAccessMask,
                        VkPipelineStageFlags dstStageMask,
                        bool byRegion);

    struct ImageDesc {
        VkImageType         fImageType;
        VkFormat            fFormat;
        uint32_t            fWidth;
        uint32_t            fHeight;
        uint32_t            fLevels;
        uint32_t            fSamples;
        VkImageTiling       fImageTiling;
        VkImageUsageFlags   fUsageFlags;
        VkFlags             fMemProps;

        ImageDesc()
            : fImageType(VK_IMAGE_TYPE_2D)
            , fFormat(VK_FORMAT_UNDEFINED)
            , fWidth(0)
            , fHeight(0)
            , fLevels(1)
            , fSamples(1)
            , fImageTiling(VK_IMAGE_TILING_OPTIMAL)
            , fUsageFlags(0)
            , fMemProps(VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) {}
    };

    static bool InitImageInfo(const GrVkGpu* gpu, const ImageDesc& imageDesc, GrVkImageInfo*);
    // Destroys the internal VkImage and VkDeviceMemory in the GrVkImageInfo
    static void DestroyImageInfo(const GrVkGpu* gpu, GrVkImageInfo*);

protected:
    void releaseImage(const GrVkGpu* gpu);
    void abandonImage();

    void setNewResource(VkImage image, VkDeviceMemory alloc);

    GrVkImageInfo   fInfo;
    bool            fIsBorrowed;

private:
    // unlike GrVkBuffer, this needs to be public so GrVkStencilAttachment can use it
    class Resource : public GrVkResource {
    public:
        Resource()
            : INHERITED()
            , fImage(VK_NULL_HANDLE)
            , fAlloc(VK_NULL_HANDLE) {
        }

        Resource(VkImage image, VkDeviceMemory alloc) : fImage(image), fAlloc(alloc) {}

        ~Resource() override {}

    private:
        void freeGPUData(const GrVkGpu* gpu) const override;

        VkImage                  fImage;
        VkDeviceMemory           fAlloc;

        typedef GrVkResource INHERITED;
    };

    // for wrapped textures
    class BorrowedResource : public Resource {
    public:
        BorrowedResource(VkImage image, VkDeviceMemory alloc) : Resource(image, alloc) {
        }
    private:
        void freeGPUData(const GrVkGpu* gpu) const override;
    };

    const Resource* fResource;

    friend class GrVkRenderTarget;
};

#endif