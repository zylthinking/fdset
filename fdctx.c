
#include "fdctx.h"

static lock_t fd_contex_lck = lock_initial;
static struct list_head fd_contex_head = LIST_HEAD_INIT(fd_contex_head);

fd_contex* fd_contex_get()
{
    fd_contex* ctx = NULL;
    lock(&fd_contex_lck);
    struct list_head* ent = fd_contex_head.next;
    if (!list_empty(ent)) {
        ctx = list_entry(ent, fd_contex, set_entry);
        list_del(ent);
    }
    unlock(&fd_contex_lck);

    if (ctx == NULL) {
        ctx = (fd_contex *) my_malloc(sizeof(fd_contex));
    }

    if (ctx != NULL) {
        INIT_LIST_HEAD(&ctx->set_entry);
        INIT_LIST_HEAD(&ctx->timer);
        ctx->token.born = atomic_inc_uint64();
        ctx->token.round = 0;
    }
    return ctx;
}

void fd_contex_put(fd_contex* ctx)
{
    ctx->token.round = 0;
    assert2(list_empty(&ctx->timer), "timer list does not empty");
    lock(&fd_contex_lck);
    list_add_tail(&ctx->set_entry, &fd_contex_head);
    unlock(&fd_contex_lck);
}

static LIST_HEAD(imp);
implement_t* implement_by_type(int32_t type)
{
    struct list_head* ent;
    for (ent = imp.next; ent != &imp; ent = ent->next) {
        implement_t* cur = list_entry(ent, implement_t, entry);
        if (cur->key == type) {
            return cur;
        }
    }
    return NULL;
}

void implement_register(implement_t* implement)
{
    struct list_head* ent = &implement->entry;
    list_add_tail(ent, &imp);
}
